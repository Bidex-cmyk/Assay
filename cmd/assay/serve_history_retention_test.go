package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/api"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/temporal"
)

var serveTestAsset = mechanics.Asset{
	Code:   "AQUA",
	Issuer: "GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA",
}

func retentionObs(day int) temporal.Observation {
	return temporal.Observation{
		Asset: serveTestAsset,
		At:    time.Date(2026, 9, day, 0, 0, 0, 0, time.UTC),
	}
}

// TestServeRejectsInvalidHistoryRetention covers the usage rule: a bound below
// one is a malformed invocation (exit 2), not a store that silently keeps
// nothing.
func TestServeRejectsInvalidHistoryRetention(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, arg := range []string{"0", "-1", "not-a-number"} {
		t.Run(arg, func(t *testing.T) {
			err := runServe([]string{"-history-retention", arg}, log)
			if err == nil {
				t.Fatal("runServe accepted an invalid -history-retention")
			}
			if got := exitCodeForError(err); got != exitUsage {
				t.Fatalf("exit code = %d, want %d (usage)", got, exitUsage)
			}
		})
	}
}

// TestHistoryRetentionBoundsInMemory covers the in-memory half: the configured
// bound is the store's bound, and it is enforced as observations arrive.
func TestHistoryRetentionBoundsInMemory(t *testing.T) {
	store, err := openHistory("", 3)
	if err != nil {
		t.Fatalf("openHistory: %v", err)
	}
	defer func() { _ = store.Close() }()

	if got := store.RetentionLimit(); got != 3 {
		t.Fatalf("RetentionLimit = %d, want 3", got)
	}
	for day := 1; day <= 5; day++ {
		if err := store.Append(retentionObs(day)); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if got := store.Len(serveTestAsset); got != 3 {
		t.Fatalf("Len = %d, want the bound of 3", got)
	}
}

// TestHistoryRetentionBoundsFileBacked covers the file-backed half: the bound
// applies while loading as well as while appending, so reopening the same log
// with a smaller bound keeps the newest observations only.
func TestHistoryRetentionBoundsFileBacked(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	store, err := openHistory(path, 4)
	if err != nil {
		t.Fatalf("openHistory: %v", err)
	}
	for day := 1; day <= 4; day++ {
		if err := store.Append(retentionObs(day)); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if got := store.RetentionLimit(); got != 4 {
		t.Fatalf("RetentionLimit = %d, want 4", got)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := openHistory(path, 2)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = reopened.Close() }()

	if got := reopened.RetentionLimit(); got != 2 {
		t.Fatalf("RetentionLimit after reopen = %d, want 2", got)
	}
	kept := reopened.List(serveTestAsset)
	if len(kept) != 2 {
		t.Fatalf("retained observations = %d, want 2", len(kept))
	}
	if want := retentionObs(4).At; !kept[1].At.Equal(want) {
		t.Fatalf("newest retained observation = %s, want %s", kept[1].At, want)
	}
}

// TestHistoryEndpointReportsConfiguredRetention covers the consumer-facing
// half: /api/v1/history states the bound it read against, so an operator can
// confirm -history-retention took effect.
func TestHistoryEndpointReportsConfiguredRetention(t *testing.T) {
	store, err := openHistory("", 7)
	if err != nil {
		t.Fatalf("openHistory: %v", err)
	}
	defer func() { _ = store.Close() }()

	srv := api.NewServer(nil)
	srv.History = store

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/history?asset="+serveTestAsset.String(), nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Retention int `json:"retention"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Retention != 7 {
		t.Fatalf("retention = %d, want the configured 7", body.Retention)
	}
}
