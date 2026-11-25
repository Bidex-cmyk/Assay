package mechanics_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/eval"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/horizon"
)

func TestUndeterminedRateTracking(t *testing.T) {
	eng := mechanics.NewEngine()

	// --- Subject 1: unreachable Horizon source ---
	subject1 := mechanics.Subject{
		Asset: mechanics.Asset{Code: "TEST", Issuer: "GBTEST1234567890ABCDEF0123456789ABCDEF01"},
		Stat:  nil,
		Issuer: &horizon.Account{
			HomeDomain: "",
		},
		Directory:            nil,
		DirectoryErr:         "",
		Blocked:              nil,
		BlockedErr:           "",
		ScannedAt:            time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
		FetchedAt:            time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
	}

	rep1, err := eng.Run(context.Background(), &subject1)
	if err != nil {
		t.Fatalf("run subject1: %v", err)
	}

	if !rep1.Undetermined {
		t.Fatal("subject1: expected Undetermined=true when sources not attempted")
	}
	t.Logf("subject1 undetermined_by_source: %v", rep1.UndeterminedBySource)
	t.Logf("subject1 undetermined_rate: %s", rep1.UndeterminedRate)
	t.Logf("subject1 undetermined_checks: %v", rep1.UndeterminedChecks)

	if len(rep1.UndeterminedBySource) == 0 {
		t.Fatal("subject1: expected at least one undetermined source key")
	}

	// Verify UndeterminedRate format: "numerator/denominator"
	if rep1.UndeterminedRate == "" {
		t.Fatal("subject1: expected non-empty UndeterminedRate when checks are undetermined")
	}
	var numerator, denominator int
	_, err = fmt.Sscanf(rep1.UndeterminedRate, "%d/%d", &numerator, &denominator)
	if err != nil {
		t.Fatalf("subject1: expected UndeterminedRate format 'n/d', got %s", rep1.UndeterminedRate)
	}
	if numerator <= 0 {
		t.Fatalf("subject1: expected numerator > 0, got %d", numerator)
	}
	if denominator != 4 {
		t.Fatalf("subject1: expected denominator=4 (total checks), got %d", denominator)
	}

	// --- Subject 2: definitive verdict (no undetermined) ---
	subject2 := mechanics.Subject{}
	s2, err := eval.LoadSubject("testdata", "aqua-clear-verified")
	if err != nil {
		t.Fatalf("load aqua-clear-verified: %v", err)
	}
	subject2 = *s2

	rep2, err := eng.Run(context.Background(), &subject2)
	if err != nil {
		t.Fatalf("run subject2: %v", err)
	}

	t.Logf("subject2 undetermined: %v", rep2.Undetermined)
	t.Logf("subject2 undetermined_by_source: %v", rep2.UndeterminedBySource)
	t.Logf("subject2 undetermined_rate: %s", rep2.UndeterminedRate)
	t.Logf("subject2 observation_window_start: %v", rep2.ObservationWindowStart)
	t.Logf("subject2 observation_window_end: %v", rep2.ObservationWindowEnd)

	if rep2.Undetermined {
		t.Fatal("subject2: aqua-clear-verified should not be undetermined when all sources available")
	}
	if rep2.UndeterminedRate != "" {
		t.Fatalf("subject2: expected empty UndeterminedRate when no undetermined checks, got %s", rep2.UndeterminedRate)
	}
	if rep2.ObservationWindowStart.IsZero() {
		t.Fatal("subject2: expected ObservationWindowStart to be set")
	}
	if rep2.ObservationWindowEnd.IsZero() {
		t.Fatal("subject2: expected ObservationWindowEnd to be set")
	}
	if !rep2.ObservationWindowStart.Equal(rep2.ObservationWindowEnd) {
		t.Logf("note: ObservationWindowStart=%v ObservationWindowEnd=%v", rep2.ObservationWindowStart, rep2.ObservationWindowEnd)
	}

	// --- Subject 3: skipped source ---
	subject3 := mechanics.Subject{
		Asset: mechanics.Asset{Code: "TEST", Issuer: "GBTEST1234567890ABCDEF0123456789ABCDEF02"},
		Stat:  nil,
		Issuer: &horizon.Account{
			HomeDomain: "",
		},
		Directory:            nil,
		DirectoryErr:         "",
		Blocked:              nil,
		BlockedErr:           "",
		ScannedAt:            time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
		FetchedAt:            time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
	}

	rep3, err := eng.Run(context.Background(), &subject3)
	if err != nil {
		t.Fatalf("run subject3: %v", err)
	}

	t.Logf("subject3 undetermined: %v", rep3.Undetermined)
	t.Logf("subject3 undetermined_by_source: %v", rep3.UndeterminedBySource)
	t.Logf("subject3 undetermined_rate: %s", rep3.UndeterminedRate)

	if len(rep3.UndeterminedBySource) == 0 {
		t.Fatal("subject3: expected at least one undetermined source key")
	}

	// --- Subject 4: with directory failure ---
	subject4 := mechanics.Subject{
		Asset: mechanics.Asset{Code: "TEST", Issuer: "GBTEST1234567890ABCDEF0123456789ABCDEF03"},
		Stat:  &horizon.AssetStat{
			AssetCode:   "TEST",
			AssetIssuer: "GBTEST1234567890ABCDEF0123456789ABCDEF03",
		},
		Issuer: &horizon.Account{
			HomeDomain: "example.com",
		},
		Directory:            nil,
		DirectoryErr:         "some error",
		Blocked:              nil,
		BlockedErr:           "",
		ScannedAt:            time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
		FetchedAt:            time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC),
	}

	rep4, err := eng.Run(context.Background(), &subject4)
	if err != nil {
		t.Fatalf("run subject4: %v", err)
	}

	t.Logf("subject4 undetermined: %v", rep4.Undetermined)
	t.Logf("subject4 undetermined_by_source: %v", rep4.UndeterminedBySource)
	t.Logf("subject4 undetermined_rate: %s", rep4.UndeterminedRate)

	if _, ok := rep4.UndeterminedBySource["stellar.expert/directory"]; !ok {
		t.Fatalf("subject4: expected 'stellar.expert/directory' in undetermined_by_source, got %v", rep4.UndeterminedBySource)
	}

	t.Log("--- All undetermined rate tracking tests completed successfully ---")
}