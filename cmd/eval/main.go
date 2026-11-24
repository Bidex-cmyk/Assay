// Command eval records the labelled corpus's classification, compares
// two recorded runs, and produces a confusion matrix over the corpus.
//
// It exists so a check change that moves verdicts is visible before it
// merges. Recording writes the per-subject, per-check output under a
// version identity; comparing diffs two records and reports severity,
// mechanic and evidence movements separately, so a change that alters
// many subjects while keeping the aggregate expectations stable cannot
// pass unremarked. The confusion matrix reports agreements and
// disagreements per severity level and per check, with undetermined as
// its own outcome class.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/use-assay/assay/internal/eval"
	"github.com/use-assay/assay/internal/mechanics"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "eval:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fixtures := fs.String("fixtures", "internal/mechanics/testdata", "corpus fixture root")
	out := fs.String("out", "", "write a run record to this file")
	compare := fs.String("compare", "", "compare the current run against a recorded baseline file")
	strict := fs.Bool("strict", false, "with -compare, exit non-zero when anything moved")
	confusion := fs.Bool("confusion", false, "print the confusion matrix over the labelled corpus")
	precisionRecall := fs.Bool("precision-recall", false, "with -confusion, emit precision and recall with a sample-size caveat")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("eval: %w", err)
	}
	if *out == "" && *compare == "" && !*confusion {
		return fmt.Errorf("nothing to do: pass -out to record a run, -compare to diff one, or -confusion to print the matrix")
	}

	rec, err := eval.Run(mechanics.NewEngine(), *fixtures)
	if err != nil {
		return fmt.Errorf("eval: %w", err)
	}
	captureDates, err := eval.CaptureDates(*fixtures)
	if err != nil {
		return fmt.Errorf("eval: %w", err)
	}
	if err := printFixtureAges(stdout, rec, captureDates, time.Now().UTC()); err != nil {
		return err
	}

	if *out != "" {
		if err := writeRecord(*out, rec); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(stdout, "recorded %d subjects under %s -> %s\n", len(rec.Subjects), rec.Version, *out)
	}

	if *compare != "" {
		base, err := readRecord(*compare)
		if err != nil {
			return err
		}
		diff := eval.Compare(base, rec)
		printDiff(stdout, base, rec, diff, *compare)
		if *strict && !diff.Empty() {
			return fmt.Errorf("classifier output moved since %s", *compare)
		}
	}

	if *confusion {
		matrix, err := eval.BuildConfusionMatrix(mechanics.NewEngine(), *fixtures)
		if err != nil {
			return fmt.Errorf("confusion matrix: %w", err)
		}
		matrix.PrintTo(stdout, *precisionRecall)
	}

	return nil
}

const staleFixtureAgeDays = 90

func printFixtureAges(w io.Writer, rec *eval.Record, captureDates map[string]time.Time, now time.Time) error {
	today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	for _, subject := range rec.Subjects {
		captured, ok := captureDates[subject.Dir]
		if !ok {
			return fmt.Errorf("eval: fixture manifest has no capture date for subject %s", subject.Dir)
		}
		ageDays := int(today.Sub(captured).Hours() / 24)
		ageUnit := "days"
		if ageDays == 1 || ageDays == -1 {
			ageUnit = "day"
		}
		if _, err := fmt.Fprintf(w, "fixture age: %s captured %s (%d %s old)",
			subject.Dir, captured.Format("2006-01-02"), ageDays, ageUnit); err != nil {
			return fmt.Errorf("eval: write fixture age: %w", err)
		}
		if ageDays > staleFixtureAgeDays {
			if _, err := fmt.Fprintf(w, " - STALE: older than %d days", staleFixtureAgeDays); err != nil {
				return fmt.Errorf("eval: write fixture age: %w", err)
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return fmt.Errorf("eval: write fixture age: %w", err)
		}
	}
	return nil
}

func writeRecord(path string, rec *eval.Record) error {
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode record: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func readRecord(path string) (*eval.Record, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var rec eval.Record
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &rec, nil
}

func printDiff(w io.Writer, base, current *eval.Record, diff eval.Diff, baselinePath string) {
	_, _ = fmt.Fprintf(w, "eval compare: %s (%s) -> %s\n", base.Version, baselinePath, current.Version)
	if diff.Empty() {
		_, _ = fmt.Fprintln(w, "no movement: severity, mechanics and evidence are unchanged")
		return
	}

	printMovements(w, "severity", diff.SeverityMovements)
	printMovements(w, "mechanics", diff.MechanicsMovements)
	printMovements(w, "evidence", diff.EvidenceMovements)

	if len(diff.Undetermined) > 0 {
		_, _ = fmt.Fprintln(w, "\nundetermined (excluded from movement counts, reported separately):")
		for _, dir := range diff.Undetermined {
			_, _ = fmt.Fprintf(w, "  %s\n", dir)
		}
	}
	if len(diff.Added) > 0 {
		_, _ = fmt.Fprintln(w, "\nadded to the corpus:")
		for _, dir := range diff.Added {
			_, _ = fmt.Fprintf(w, "  %s\n", dir)
		}
	}
	if len(diff.Removed) > 0 {
		_, _ = fmt.Fprintln(w, "\nremoved from the corpus:")
		for _, dir := range diff.Removed {
			_, _ = fmt.Fprintf(w, "  %s\n", dir)
		}
	}
}

func printMovements(w io.Writer, name string, moves []eval.Movement) {
	if len(moves) == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "\n%s movements (%d):\n", name, len(moves))
	for _, m := range moves {
		_, _ = fmt.Fprintf(w, "  %s\t%s: %s -> %s\n", m.Dir, m.Field, m.Before, m.After)
	}
}
