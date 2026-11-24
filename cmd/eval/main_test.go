package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/eval"
)

func TestRunNothingToDo(t *testing.T) {
	err := run(nil, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "nothing to do") {
		t.Fatalf("got %v, want nothing-to-do error", err)
	}
}

func TestOutRoundTripsThroughCompare(t *testing.T) {
	fixtures := filepath.Join("..", "..", "internal", "mechanics", "testdata")
	dir := t.TempDir()
	record := filepath.Join(dir, "record.json")
	var stdout bytes.Buffer

	if err := run([]string{"-fixtures", fixtures, "-out", record}, &stdout); err != nil {
		t.Fatalf("record: %v", err)
	}
	stdout.Reset()
	if err := run([]string{"-fixtures", fixtures, "-compare", record}, &stdout); err != nil {
		t.Fatalf("compare: %v", err)
	}
	if strings.Contains(stdout.String(), "movement (") {
		t.Fatalf("round trip reported movement:\n%s", stdout.String())
	}
}

func TestStrictFailsWhenBaselineMoves(t *testing.T) {
	fixtures := filepath.Join("..", "..", "internal", "mechanics", "testdata")
	dir := t.TempDir()
	record := filepath.Join(dir, "record.json")
	var stdout bytes.Buffer
	if err := run([]string{"-fixtures", fixtures, "-out", record}, &stdout); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	mutated := bytes.Replace(b, []byte(`"severity": "clear"`), []byte(`"severity": "high"`), 1)
	if bytes.Equal(mutated, b) {
		t.Fatal("test baseline did not contain a severity field to mutate")
	}
	if err := os.WriteFile(record, mutated, 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	err = run([]string{"-fixtures", fixtures, "-compare", record, "-strict"}, &stdout)
	if err == nil || !strings.Contains(err.Error(), "classifier output moved") {
		t.Fatalf("got %v, want strict movement failure", err)
	}
}

func TestConfusionPrintsSampleSizes(t *testing.T) {
	fixtures := filepath.Join("..", "..", "internal", "mechanics", "testdata")
	var stdout bytes.Buffer
	if err := run([]string{"-fixtures", fixtures, "-confusion"}, &stdout); err != nil {
		t.Fatalf("confusion: %v", err)
	}
	if !strings.Contains(stdout.String(), "sample_size") {
		t.Fatalf("confusion output omitted sample sizes:\n%s", stdout.String())
	}
}

func TestPrintFixtureAgesFlagsSubjectsOlderThan90Days(t *testing.T) {
	now := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	rec := &eval.Record{Subjects: []eval.SubjectResult{
		{Dir: "recent"},
		{Dir: "ninety-days"},
		{Dir: "stale"},
	}}
	dates := map[string]time.Time{
		"recent":      time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC),
		"ninety-days": time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC),
		"stale":       time.Date(2026, 8, 20, 0, 0, 0, 0, time.UTC),
	}
	var out bytes.Buffer
	if err := printFixtureAges(&out, rec, dates, now); err != nil {
		t.Fatalf("printFixtureAges: %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"recent captured 2026-11-18 (1 day old)",
		"ninety-days captured 2026-08-21 (90 days old)",
		"stale captured 2026-08-20 (91 days old) - STALE: older than 90 days",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("age output does not contain %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "ninety-days captured 2026-08-21 (90 days old) - STALE") {
		t.Error("a fixture exactly 90 days old was flagged stale")
	}
}
