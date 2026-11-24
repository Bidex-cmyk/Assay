// Command refreshfixture re-captures one corpus fixture from the URLs recorded
// in PROVENANCE.md and prints what changed, so a maintainer can judge whether a
// moved verdict reflects a real change or a regression.
//
// It requires network access and is therefore not run by CI. Invoke it through
// the make target:
//
//	make refresh-fixture SUBJECT=aqua-clear-verified
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/use-assay/assay/internal/fixtures"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, &fixtures.Refresher{Client: http.DefaultClient}))
}

type refresher interface {
	Refresh(context.Context, string, string, bool) (*fixtures.Result, error)
}

func run(args []string, stdout, stderr io.Writer, r refresher) int {
	fs := flag.NewFlagSet("refreshfixture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	subject := fs.String("subject", "", "fixture directory to re-capture, e.g. aqua-clear-verified")
	root := fs.String("root", "internal/mechanics/testdata", "fixture root holding PROVENANCE.md and manifest.json")
	dryRun := fs.Bool("dry-run", false, "show the diff without writing")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *subject == "" {
		_, _ = fmt.Fprintln(stderr, "usage: refresh-fixture -subject <dir> [-root <dir>] [-dry-run]")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ref := r
	res, err := ref.Refresh(ctx, *root, *subject, !*dryRun)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "refresh %s: %v\n", *subject, err)
		return 1
	}

	if len(res.Changed) == 0 {
		_, _ = fmt.Fprintf(stdout, "%s: no change; the fixtures match the live sources\n", *subject)
		return 0
	}
	for _, c := range res.Changed {
		_, _ = fmt.Fprint(stdout, fixtures.Unified(c.File, c.Old, c.New))
	}
	if *dryRun {
		_, _ = fmt.Fprintf(stdout, "\n%s: %d file(s) would change (dry run; nothing written)\n", *subject, len(res.Changed))
		return 0
	}
	_, _ = fmt.Fprintf(stdout, "\n%s: %d file(s) updated and capture date refreshed\n", *subject, len(res.Changed))
	return 0
}
