package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/fixtures"
)

type fakeRefresher struct {
	result *fixtures.Result
	err    error
}

func (f *fakeRefresher) Refresh(context.Context, string, string, bool) (*fixtures.Result, error) {
	return f.result, f.err
}

func TestRunMissingSubject(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run(nil, &stdout, &stderr, &fakeRefresher{})
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("-subject")) {
		t.Fatalf("missing usage: %s", stderr.String())
	}
}

func TestRunDryRunWritesNothing(t *testing.T) {
	r := &fakeRefresher{result: &fixtures.Result{Changed: []fixtures.Change{
		{File: "demo/asset.json", Old: []byte("old"), New: []byte("new")},
	}}}
	var stdout, stderr bytes.Buffer
	code := run([]string{"-subject", "demo", "-dry-run"}, &stdout, &stderr, r)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("would change")) {
		t.Fatalf("dry-run output: %s", stdout.String())
	}
}

func TestRunRefresherError(t *testing.T) {
	r := &fakeRefresher{err: errors.New("source unavailable")}
	var stdout, stderr bytes.Buffer
	code := run([]string{"-subject", "demo"}, &stdout, &stderr, r)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("source unavailable")) {
		t.Fatalf("missing error: %s", stderr.String())
	}
}

func TestRunDryRunWritesNothingWithHTTPSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"asset_code":"TEST","changed":true}`))
	}))
	t.Cleanup(srv.Close)

	root := t.TempDir()
	subjectDir := filepath.Join(root, "demo")
	if err := os.MkdirAll(subjectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subjectDir, "asset.json"), []byte(`{"asset_code":"TEST","changed":false}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	provenance := "# Fixture provenance\n\n| file | source URL |\n| --- | --- |\n| `demo/asset.json` | " + srv.URL + "/asset |\n"
	if err := os.WriteFile(filepath.Join(root, "PROVENANCE.md"), []byte(provenance), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := `{"subjects":[{"fixture":"demo","capture_date":"2026-01-01"}]}`
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &fixtures.Refresher{Client: srv.Client(), Now: func() time.Time {
		return time.Date(2026, 2, 2, 0, 0, 0, 0, time.UTC)
	}}
	var stdout, stderr bytes.Buffer
	code := run([]string{"-subject", "demo", "-root", root, "-dry-run"}, &stdout, &stderr, r)
	if code != 0 {
		t.Fatalf("exit = %d, stderr=%s", code, stderr.String())
	}
	got, err := os.ReadFile(filepath.Join(subjectDir, "asset.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "changed\":true") {
		t.Fatal("dry-run wrote the HTTP source change")
	}
	if !strings.Contains(stdout.String(), "would change") {
		t.Fatalf("dry-run output missing diff: %s", stdout.String())
	}
}
