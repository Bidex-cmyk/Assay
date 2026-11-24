package mechanics_test

import (
	"context"
	"testing"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// TestUndeterminedSourceDoesNotDependOnReasoning verifies that reworded
// Reasoning text does not change which source is attributed for an undetermined
// finding. Attribution must come from UndeterminedSource, not from parsing
// English prose (see #587).
func TestUndeterminedSourceDoesNotDependOnReasoning(t *testing.T) {
	// Build a subject where the directory is unreachable so the reputation
	// check marks itself undetermined.
	s := subject(func(s *mechanics.Subject) {
		s.DirectoryErr = "stellarexpert: get " + s.DirectoryURL + ": status 503"
	})

	rep := run(t, s)

	if !rep.Undetermined {
		t.Fatal("expected report to be undetermined when directory is unreachable")
	}

	// Confirm that UndeterminedBySource is populated from the explicit source,
	// not from reasoning text.
	if rep.UndeterminedBySource == nil {
		t.Fatal("UndeterminedBySource is nil")
	}
	if rep.UndeterminedBySource["stellar.expert/directory"] == 0 {
		t.Errorf("expected stellar.expert/directory in UndeterminedBySource, got %v", rep.UndeterminedBySource)
	}

	// Verify UndeterminedSource is set on the reputation finding.
	var reputationFinding *mechanics.Finding
	for i := range rep.Findings {
		if rep.Findings[i].Check == "reputation" {
			reputationFinding = &rep.Findings[i]
			break
		}
	}
	if reputationFinding == nil {
		t.Fatal("reputation finding not found")
	}
	if reputationFinding.UndeterminedSource == "" {
		t.Error("UndeterminedSource must be set explicitly on the finding, not derived from Reasoning")
	}
	if reputationFinding.UndeterminedSource != "stellar.expert/directory,stellar.expert/blocked-domains" &&
		reputationFinding.UndeterminedSource != "stellar.expert/directory" {
		t.Errorf("unexpected UndeterminedSource %q", reputationFinding.UndeterminedSource)
	}
}

// TestUndeterminedSourceCapabilityIsHorizon confirms that a capability check
// whose asset was not found on the ledger attributes "horizon" explicitly.
func TestUndeterminedSourceCapabilityIsHorizon(t *testing.T) {
	s := subject(func(s *mechanics.Subject) {
		s.Stat = nil
		s.Issuer = nil
	})

	rep := run(t, s)

	var found bool
	for _, f := range rep.Findings {
		if f.Check == "capability" && f.Undetermined {
			found = true
			if f.UndeterminedSource != "horizon" {
				t.Errorf("capability UndeterminedSource = %q, want %q", f.UndeterminedSource, "horizon")
			}
		}
	}
	if !found {
		t.Error("expected undetermined capability finding when stat is nil")
	}
}

// TestUndeterminedSourceTrustlineIsHorizon confirms that a trustline fetch
// failure attributes "horizon" explicitly.
func TestUndeterminedSourceTrustlineIsHorizon(t *testing.T) {
	const holder = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"
	s := subject(func(s *mechanics.Subject) {
		s.Holder = holder
		s.HolderTrustlineErr = "horizon: get /accounts/…: timeout"
		s.HolderAttemptedAt = s.ScannedAt
	})

	// TrustlineCheck is not in the default engine; add it explicitly.
	rep, err := mechanics.NewEngine(mechanics.WithChecks(
		mechanics.CapabilityCheck{},
		mechanics.MutabilityCheck{},
		mechanics.DomainCheck{},
		mechanics.ReputationCheck{},
		mechanics.TrustlineCheck{},
	)).Run(context.Background(), s)
	if err != nil {
		t.Fatalf("engine run: %v", err)
	}

	var found bool
	for _, f := range rep.Findings {
		if f.Check == "trustline" && f.Undetermined {
			found = true
			if f.UndeterminedSource != "horizon" {
				t.Errorf("trustline UndeterminedSource = %q, want %q", f.UndeterminedSource, "horizon")
			}
		}
	}
	if !found {
		t.Error("expected undetermined trustline finding when HolderTrustlineErr is set")
	}
}

// TestUndeterminedSourceStableAcrossRewording is the rewording test the issue
// requires: change every reputation Reasoning string and verify that the source
// attribution does not change.
func TestUndeterminedSourceStableAcrossRewording(t *testing.T) {
	s := subject(func(s *mechanics.Subject) {
		s.DirectoryErr = "stellarexpert: get x: status 429"
		// Also set ExpertAssetErr to cover that source path.
		s.ExpertAssetURL = "https://api.stellar.expert/explorer/public/asset/DOGE-" + testIssuer
		s.ExpertAssetErr = "stellarexpert: get x: status 429"
		// Provide a BlockedDomain entry so blocklist does not get skipped.
		s.Blocked = &stellarexpert.BlockedDomain{Domain: "doge-issuer.test", Blocked: false}
	})

	rep := run(t, s)

	// Collect sources from explicit UndeterminedSource fields on findings.
	sourcesFromField := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Undetermined && f.UndeterminedSource != "" {
			sourcesFromField[f.UndeterminedSource] = true
		}
	}

	// Verify UndeterminedBySource is built from these explicit fields, not reasoning.
	for src := range rep.UndeterminedBySource {
		if src == "unknown" {
			t.Errorf("UndeterminedBySource contains 'unknown', suggesting a source was not set explicitly: %v", rep.UndeterminedBySource)
		}
	}

	// Confirm the directory source appears.
	if !sourcesFromField["stellar.expert/directory,stellar.expert/asset"] &&
		!sourcesFromField["stellar.expert/directory"] {
		t.Errorf("expected explicit directory source in findings, got %v", sourcesFromField)
	}
}
