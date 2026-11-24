// Command assay scans Stellar assets for issuer trap mechanics.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/use-assay/assay/internal/api"
	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/bundle"
	// Aliased because this file already has a local history() for the CLI's
	// evidence view; this package is the persisted observation store behind the
	// HTTP endpoint, a different thing.
	historystore "github.com/use-assay/assay/internal/history"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/replay"
	"github.com/use-assay/assay/internal/scan"
	"github.com/use-assay/assay/internal/temporal"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		var exitErr *commandExitError
		if errors.As(err, &exitErr) {
			if exitErr.err == nil {
				os.Exit(exitErr.code)
			}
			fmt.Fprintln(os.Stderr, "assay:", exitErr.err)
			os.Exit(exitErr.code)
		}
		fmt.Fprintln(os.Stderr, "assay:", err)
		os.Exit(exitCodeForError(err))
	}
}

// commandDeps are the process-level dependencies the subcommands use. They are
// grouped so dispatch, flag handling and output formatting can be tested
// without a network or a real server. The CLI is how the attestation pipeline
// is driven — `make attest` shells out to `assay attestation -raw` and pipes
// the output into a transaction — so its parsing and formatting is a contract
// worth pinning.
type commandDeps struct {
	stdout io.Writer
	stderr io.Writer
	// scan fetches and classifies one asset. It is injected so tests never
	// touch the network.
	scan func(context.Context, mechanics.Asset) (*mechanics.Report, error)
	// scanner builds a production Scanner for the given SEP-0042 lists and
	// cache policy. It is injected so a test can observe what a command wires
	// without constructing a transport.
	scanner func([]string, scan.Options) *scan.Scanner
	// serve starts the HTTP API. It is injected so dispatch can be tested
	// without binding a port.
	serve func([]string, *slog.Logger) error
}

// defaultDeps wires the real production sources.
func defaultDeps() commandDeps {
	return commandDeps{
		stdout: os.Stdout,
		stderr: os.Stderr,
		scan: func(ctx context.Context, a mechanics.Asset) (*mechanics.Report, error) {
			return scan.New().Scan(ctx, a)
		},
		scanner: newScanner,
		serve:   runServe,
	}
}

// flagSetOutput is where a command's flag list is printed. It is a variable so
// a test can capture the flags a command registers without starting it.
var flagSetOutput io.Writer = os.Stderr

// newFlagSet is the one place a command's FlagSet is built, so every command
// reports help to the same writer.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(flagSetOutput)
	return fs
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `usage:
  assay scan CODE-ISSUER          classify one asset and print the report as JSON
  assay attestation CODE-ISSUER   print the on-chain attest() arguments for one asset
  assay verify [-json] [-max-age SECS] [-differential [-rpc URL]]
               [-registry-rpc URL] [-contract C...] [-network NETWORK] CODE-ISSUER
                                  compare a live scan with the on-chain attestation
                                  (with -differential, also re-read issuer flags via RPC)
  assay verify -bundle IN [-json]
                                  verify an offline bundle without a network
  assay diff [-json] A.json B.json
                                  compare two saved reports and print what changed
  assay history [-guarantee] [-raw] [-server URL] CODE-ISSUER
                                  print the asset's observation history
  assay registry-history [-registry-rpc URL] [-rpc URL] [-contract C...] [-network NETWORK] [-json] ASSET
                                  print the registry's attest/revoke events for an asset
                                  (CODE-ISSUER or SAC address), bounded by RPC event retention
  assay verify-preimage [-version VERSION] HASH PREIMAGE
                                  compare a stored hash with canonical preimage bytes
  assay checks                    print every check's ID and description
  assay serve [-addr] [-history PATH] [-history-retention N] [-observe FILE] [-observe-interval DURATION]
                                  serve the HTTP API and UI
  assay version                   print scanner identity, preimage encodings
                                  and build (VCS, Go) information

Commands that scan also accept:
  -cache-directory-ttl D   reuse a curated directory answer for D (0 disables)
  -cache-blocklist-ttl D   reuse a blocklist answer for D (0 disables)
  -no-cache                re-fetch curated sources and asset lists on every scan

Commands that consume SEP-0042 asset lists (scan, attestation, history, serve)
also accept:
  -asset-lists URL[,URL...]
                           SEP-0042 Stellar Asset Lists to consume
                           (repeatable). No list is used by default.

The scan command additionally accepts:
  -record DIR             save every upstream response into DIR with a
                          manifest, for later -replay
  -replay DIR             serve every upstream response from a recording;
                          an unrecorded request fails loudly instead of
                          reaching the network

The attestation command additionally accepts:
  -preimage-version V     render the preimage under encoding V (v1, v2, v3,
                          v4 or assay-evidence-vN) instead of the one the
                          report binds, so an already-recorded hash can be
                          reproduced from a fresh scan
  -bundle OUT             also write an offline verification bundle (raw
                          source bytes, report, preimage, digest) to OUT

The history command additionally accepts:
  -server URL             fetch history from a running assay server instead of
                          computing from a local scan (e.g. http://localhost:8080)

The verify command additionally accepts:
  -registry-rpc URL       Soroban RPC endpoint for the registry (env ASSAY_RPC_URL)
  -contract ID            registry contract id (env ASSAY_CONTRACT_ID)
  -network NAME           network used to derive the SAC id (env ASSAY_NETWORK)

The serve command additionally accepts:
  -history-retention N    observations kept per asset (default 256)
  -observe FILE           path to asset list file for scheduled observation
  -observe-interval DURATION
                          interval between scheduled scans (default 6h)
  -trusted-proxies CIDR[,CIDR...]
                          trusted reverse proxy CIDRs for rate limiting
`)
}

func run(args []string) error { return runWith(args, defaultDeps()) }

// runWith is the testable entry point: it performs dispatch only, consuming
// output writers and a scan function from d.
func runWith(args []string, d commandDeps) error {
	if len(args) == 0 {
		usage(d.stderr)
		return usagef("no command given")
	}

	log := slog.New(slog.NewTextHandler(d.stderr, nil))

	switch args[0] {
	case "scan":
		return runScan(args[1:], d)
	case "attestation":
		return runAttestation(args[1:], d)
	case "history":
		return runHistory(args[1:], d)
	case "verify":
		return runVerify(args[1:])
	case "diff":
		return runDiff(args[1:], d)
	case "registry-history":
		return runRegistryHistory(args[1:], d)
	case "verify-preimage":
		return runVerifyPreimage(args[1:])
	case "checks":
		return runChecks(args[1:], d)
	case "serve":
		return d.serve(args[1:], log)
	case "version", "-version", "--version":
		// The identity form works both as a subcommand and as the
		// conventional top-level flag, so `assay version`, `assay -version`
		// and `assay --version` all answer the same thing.
		return runVersion(args[1:], d)
	default:
		usage(d.stderr)
		return usagef("unknown command %q", args[0])
	}
}

func runScan(args []string, d commandDeps) error {
	fs := newFlagSet("scan")
	assetLists := assetListFlags(fs)
	cache := cacheFlags(fs)
	recordDir := fs.String("record", "",
		"save every upstream response into DIR for later -replay")
	replayDir := fs.String("replay", "",
		"serve every upstream response from a recording made with -record")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usagef("scan takes exactly one asset (CODE-ISSUER)")
	}
	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}
	if *recordDir != "" && *replayDir != "" {
		return fmt.Errorf("-record and -replay are mutually exclusive")
	}

	scanFn, finish, err := scanFuncForRecording(assetLists(), cache(), d, *recordDir, *replayDir)
	if err != nil {
		return err
	}
	// A recording is closed even when the scan fails: a failed live scan is
	// exactly the case worth reproducing, so everything it did fetch is kept.
	defer finish()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := scanFn(ctx, asset)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(d.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("scan: write report: %w", err)
	}
	return nil
}

// scanFuncForRecording returns the scan function for the scanning subcommands
// plus a finish hook that must run after the scan, whatever its outcome.
//
// With neither flag it returns the injected dependency unchanged, so dispatch
// tests never construct a scanner or touch a transport. -record wraps the
// fetchers' transport in a recorder; -replay replaces it with the recording.
// Nothing else about the scan changes — same fetches, same engine — which is
// what makes a replayed report comparable to the recorded one.
func scanFuncForRecording(lists []string, opts scan.Options, d commandDeps, recordDir, replayDir string) (func(context.Context, mechanics.Asset) (*mechanics.Report, error), func(), error) {
	if recordDir == "" && replayDir == "" {
		return scanFuncFor(lists, opts, d), func() {}, nil
	}
	scanner := d.scanner(lists, opts)

	if recordDir != "" {
		rec, err := replay.NewRecorder(recordDir, scanner.Horizon.HTTP.Transport)
		if err != nil {
			return nil, func() {}, fmt.Errorf("record: %w", err)
		}
		wireTransport(scanner, rec)
		return scanner.Scan, func() {
			if err := rec.Close(); err != nil {
				// The scan's report is already on stdout or already failed;
				// the recording failing must not mask either, but it must be
				// said out loud — a silently missing recording turns the
				// next -replay into a confusing "unrecorded request".
				_, _ = fmt.Fprintln(d.stderr, "assay: recording not written:", err)
			}
		}, nil
	}

	rp, err := replay.NewReplayer(replayDir)
	if err != nil {
		return nil, func() {}, fmt.Errorf("replay: %w", err)
	}
	wireTransport(scanner, rp)
	return scanner.Scan, func() {}, nil
}

// wireTransport points every fetcher's client at the same transport. The
// fetchers build their http.Clients with the default transport and a timeout;
// replacing the transport is the one seam every source shares.
func wireTransport(s *scan.Scanner, rt http.RoundTripper) {
	for _, c := range []*http.Client{
		s.Horizon.HTTP, s.Toml.HTTP, s.Expert.HTTP, s.Lists.HTTP,
	} {
		c.Transport = rt
	}
}

// scanFuncFor returns the scan function the scanning subcommands use. When no
// SEP-0042 list is configured it returns the injected dependency, so dispatch
// tests never touch the network; when lists are named it wires a production
// scanner configured to consult them.
func scanFuncFor(lists []string, opts scan.Options, d commandDeps) func(context.Context, mechanics.Asset) (*mechanics.Report, error) {
	if len(lists) == 0 && opts == scan.DefaultOptions() {
		return d.scan
	}
	return d.scanner(lists, opts).Scan
}

// assetListFlags registers the -asset-lists flag shared by every command that
// scans, and returns a constructor for the URLs it names.
//
// No list is a default, and that is deliberate: shipping one would hard-code a
// provider's curation as authoritative for every scan, and would add evidence
// to every report — which changes every evidence_hash, including for assets
// already attested. A caller opts in, and each list it names is attributed
// separately by name and URL. See docs/asset-lists.md.
func assetListFlags(fs *flag.FlagSet) func() []string {
	var urls listFlag
	fs.Var(&urls, "asset-lists",
		"SEP-0042 Stellar Asset List URLs to consume, comma-separated or repeated; none by default")
	return func() []string {
		return append([]string(nil), urls...)
	}
}

// newScanner returns a production Scanner configured to consult the given
// SEP-0042 asset lists under the given reputation cache policy.
func newScanner(lists []string, opts scan.Options) *scan.Scanner {
	sc := scan.NewWithOptions(opts)
	sc.AssetListURLs = lists
	return sc
}

// cacheFlags registers the reputation-cache flags shared by every command that
// scans, and returns the policy they describe. docs/caching.md tells an operator
// to reach for these flags, so every command the document names has to register
// them.
func cacheFlags(fs *flag.FlagSet) func() scan.Options {
	defaults := scan.DefaultOptions()
	directoryTTL := fs.Duration("cache-directory-ttl", defaults.ReputationDirectoryTTL,
		"reuse a curated directory answer for this long (0 disables)")
	blocklistTTL := fs.Duration("cache-blocklist-ttl", defaults.ReputationBlocklistTTL,
		"reuse a blocklist answer for this long (0 disables)")
	noCache := fs.Bool("no-cache", false, "re-fetch curated sources and asset lists on every scan")
	return func() scan.Options {
		opts := scan.Options{
			ReputationDirectoryTTL: *directoryTTL,
			ReputationBlocklistTTL: *blocklistTTL,
			NoReputationCache:      *noCache,
			AssetListTTL:           defaults.AssetListTTL,
		}
		// -no-cache means every consumed signal is re-read, not only the
		// reputation endpoints; a cached asset list would contradict its help.
		if *noCache {
			opts.AssetListTTL = 0
		}
		return opts
	}
}

// listFlag collects repeated -asset-lists values as well as comma-separated
// ones, so both forms work:
//
//	-asset-lists=a,b -asset-lists=c
//	-asset-lists a -asset-lists b
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

// runAttestation prints the arguments of an on-chain attest() call for one
// asset, derived from a live scan.
//
// It deliberately does not submit anything. Signing belongs to whoever holds
// the attester key, and keeping derivation separate from submission means the
// numbers going on-chain can be inspected — and the evidence hash independently
// recomputed from -preimage — before a key ever touches them.
//
// -preimage-version renders the report under a historical encoding instead of
// the newest one it binds: reproducing an attestation already on chain means
// re-deriving the bytes it was actually hashed over. The flag takes v1 … v4
// or the full assay-evidence-vN line; an empty value keeps the default
// (newest binding wins). A verifier compares like with like because of it.
func runAttestation(args []string, d commandDeps) error {
	fs := newFlagSet("attestation")
	assetLists := assetListFlags(fs)
	cache := cacheFlags(fs)
	preimage := fs.Bool("preimage", false, "include the canonical bytes evidence_hash commits to")
	raw := fs.Bool("raw", false, "print only the attest() arguments, tab-separated, for scripting")
	preimageVersion := fs.String("preimage-version", "",
		"render the preimage under this encoding: v1, v2, v3, v4 or a full assay-evidence-vN line (default: the one the report binds)")
	bundleOut := fs.String("bundle", "",
		"also write an offline verification bundle (raw source bytes, report, preimage, digest) to this path")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usagef("attestation takes exactly one asset (CODE-ISSUER)")
	}
	// The encoding is validated before the live scan: a mistyped version is a
	// usage error, and discovering it after a 30-second fetch would waste the
	// fetch and muddy the error.
	if *preimageVersion != "" {
		if _, err := attest.NormalizePreimageVersion(*preimageVersion); err != nil {
			return fmt.Errorf("attestation: %w", err)
		}
	}
	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("attestation: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scanFn := scanFuncFor(assetLists(), cache(), d)
	finish := func() {}
	recordingDir := ""
	if *bundleOut != "" {
		dir, err := os.MkdirTemp("", "assay-bundle-*")
		if err != nil {
			return fmt.Errorf("create bundle recording directory: %w", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()
		recordingDir = dir
		// Record into a private directory first; the archive is written only
		// after the report is derived, so a failed scan leaves no half bundle.
		scanFn, finish, err = scanFuncForRecording(assetLists(), cache(), d, recordingDir, "")
		if err != nil {
			return err
		}
	}

	report, err := scanFn(ctx, asset)
	if err != nil {
		return err
	}
	// Derivation happens before any output. An undetermined scan has no
	// attestation to print, and nothing may reach stdout that a pipeline could
	// mistake for values.
	params, err := attest.FromReportAs(report, *preimageVersion)
	if err != nil {
		return fmt.Errorf("attestation: %w", err)
	}

	if *bundleOut != "" {
		// Close the recording before packaging: the manifest and bodies are
		// written by Close, and a bundle built from a still-open recorder would
		// be missing every response.
		finish()
		if err := bundle.Write(*bundleOut, report, params, recordingDir); err != nil {
			return fmt.Errorf("write verification bundle %s: %w", *bundleOut, err)
		}
		_, _ = fmt.Fprintf(d.stderr, "assay: wrote verification bundle %s\n", *bundleOut)
	}

	if *raw {
		// Without a requested version the format is unchanged: SEVERITY,
		// FLAGS, HASH. With one, a fourth field carries the hash the report
		// renders under the version the current binary would pick, so a
		// caller can tell "the evidence changed" (neither matches the
		// recorded hash) apart from "the recorded hash belongs to another
		// encoding" (only the current rendering matches it).
		if *preimageVersion == "" {
			if _, err := fmt.Fprintf(d.stdout, "%d\t%d\t%s\n", params.Severity, params.Flags, params.EvidenceHash); err != nil {
				return fmt.Errorf("attestation: write: %w", err)
			}
			return nil
		}
		current, err := attest.FromReport(report)
		if err != nil {
			return fmt.Errorf("attestation: %w", err)
		}
		if _, err := fmt.Fprintf(d.stdout, "%d\t%d\t%s\t%s\n",
			params.Severity, params.Flags, params.EvidenceHash, current.EvidenceHash); err != nil {
			return fmt.Errorf("attestation: write: %w", err)
		}
		return nil
	}
	if !*preimage {
		params.Preimage = ""
	}

	enc := json.NewEncoder(d.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(params); err != nil {
		return fmt.Errorf("attestation: write: %w", err)
	}
	return nil
}

func runHistory(args []string, d commandDeps) error {
	fs := newFlagSet("history")
	assetLists := assetListFlags(fs)
	cache := cacheFlags(fs)
	guarantee := fs.Bool("guarantee", false, "exit non-zero when there is no history")
	raw := fs.Bool("raw", false, "print only the history, tab-separated, for scripting")
	serverURL := fs.String("server", "", "fetch history from a running assay server (e.g. http://localhost:8080)")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usagef("history takes exactly one asset (CODE-ISSUER)")
	}

	asset, err := scan.ParseAsset(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("history: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var hist []historyEntry

	if *serverURL != "" {
		// Fetch history from server.
		hist, err = fetchHistoryFromServer(ctx, *serverURL, asset.String())
		if err != nil {
			return err
		}
	} else {
		// Compute history from local scan (existing behavior).
		report, err := scanFuncFor(assetLists(), cache(), d)(ctx, asset)
		if err != nil {
			return err
		}
		hist = history(report)
	}

	if len(hist) == 0 {
		msg := "assay history: no observations for " + asset.String()
		_, _ = fmt.Fprintln(d.stdout, msg)
		if *guarantee {
			return fmt.Errorf("no history")
		}
		return nil
	}

	if *raw {
		for _, h := range hist {
			_, _ = fmt.Fprintf(d.stdout, "%s\t%s\t%s\t%s\n", h.Asset, h.Severity, h.Transition, h.Reason)
		}
		return nil
	}

	enc := json.NewEncoder(d.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(hist); err != nil {
		return fmt.Errorf("history: write: %w", err)
	}
	return nil
}

// fetchHistoryFromServer fetches history from a running assay server's
// /api/v1/history endpoint.
func fetchHistoryFromServer(ctx context.Context, serverURL, asset string) ([]historyEntry, error) {
	// Ensure serverURL has a scheme.
	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "http://" + serverURL
	}
	// Trim trailing slash.
	serverURL = strings.TrimSuffix(serverURL, "/")

	url := serverURL + "/api/v1/history?asset=" + asset
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("history: build request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("history: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("history: server returned %d: %s", resp.StatusCode, string(body))
	}

	// Parse the server's history response.
	var serverResp struct {
		State        string `json:"state"`
		Reason       string `json:"reason,omitempty"`
		Count        int    `json:"count"`
		Observations []struct {
			Asset              string    `json:"asset"`
			At                 time.Time `json:"at"`
			Mechanics          int       `json:"mechanics"`
			BaseSeverity       string    `json:"base_severity"`
			Severity           string    `json:"severity"`
			Undetermined       bool      `json:"undetermined"`
			UndeterminedChecks []string  `json:"undetermined_checks"`
			Reason             string    `json:"reason,omitempty"`
		} `json:"observations"`
		Transitions []struct {
			State          string   `json:"state"`
			Reason         string   `json:"reason"`
			AddedNames     []string `json:"added_names"`
			RemovedNames   []string `json:"removed_names"`
			Attribution    string   `json:"attribution"`
			SeverityBefore string   `json:"severity_before"`
			SeverityAfter  string   `json:"severity_after"`
			Accountability struct {
				From    string `json:"from"`
				To      string `json:"to"`
				Changed bool   `json:"changed"`
				State   string `json:"state"`
			} `json:"accountability"`
		} `json:"transitions"`
		LatestAt      *time.Time `json:"latest_at,omitempty"`
		LatestAgeSecs *int64     `json:"latest_age_secs,omitempty"`
		Retention     int        `json:"retention"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&serverResp); err != nil {
		return nil, fmt.Errorf("history: decode response: %w", err)
	}

	// Convert server response to historyEntry format.
	hist := make([]historyEntry, 0, len(serverResp.Observations))
	for _, obs := range serverResp.Observations {
		// Determine transition for this observation.
		// The server response includes transitions array, but we need to map
		// each observation to its transition. For simplicity, we use the
		// observation's severity and a generic reason.
		transition := "unknown"
		reason := obs.BaseSeverity
		if obs.Undetermined {
			reason = "undetermined: " + strings.Join(obs.UndeterminedChecks, ", ")
		}

		hist = append(hist, historyEntry{
			Asset:      obs.Asset,
			Severity:   obs.Severity,
			Transition: transition,
			Reason:     reason,
			Time:       obs.At,
		})
	}

	return hist, nil
}

// history extracts the observation history from a report. The observations are
// the evidence entries, in time order. When there are none, it returns an empty
// slice so the caller can print the clear message.
func history(rep *mechanics.Report) []historyEntry {
	if rep == nil {
		return nil
	}
	hist := make([]historyEntry, 0, len(rep.Evidence))
	for _, e := range rep.Evidence {
		hist = append(hist, historyEntry{
			Asset:      rep.Asset.String(),
			Severity:   rep.Severity.String(),
			Transition: transition(e.Claim),
			Reason:     e.Claim,
			Time:       e.RetrievedAt.Time(),
		})
	}
	return hist
}

// transition reduces a plain-language evidence claim to the term the
// consumer prints: whatever the issuer was observed doing, or unknown when a
// source did not answer.
func transition(claim string) string {
	if claim == "" {
		return "unknown"
	}
	low := strings.ToLower(claim)
	for _, s := range candidateTransitions {
		if strings.Contains(low, s) {
			return s
		}
	}
	return "unknown"
}

// candidateTransitions is the set of ways an observation can read in this
// project. It is deliberately small: the history view does not re-derive the
// verdict, it only reports what each observation says.
var candidateTransitions = []string{
	"malicious",
	"listed as",
	"blocked",
	"unverified",
	"not retrievable",
	"not present",
	"credits",
	"claims",
	"borrow",
	"pay",
}

type historyEntry struct {
	Asset      string    `json:"asset"`
	Severity   string    `json:"severity"`
	Transition string    `json:"transition"`
	Reason     string    `json:"reason"`
	Time       time.Time `json:"time"`
}

// openHistory returns the store serve records into: in memory when no path is
// configured, file-backed when one is, and in both cases bounded by retention
// observations per asset.
func openHistory(path string, retention int) (*historystore.Store, error) {
	if path == "" {
		return historystore.NewWithRetention(retention), nil
	}
	store, err := historystore.OpenWithRetention(path, retention)
	if err != nil {
		return nil, fmt.Errorf("serve: history: %w", err)
	}
	return store, nil
}

func runServe(args []string, log *slog.Logger) error {
	fs := newFlagSet("serve")
	assetLists := assetListFlags(fs)
	cache := cacheFlags(fs)
	addr := fs.String("addr", ":8080", "listen address")
	historyPath := fs.String("history", "",
		"path to the observation history log (JSON Lines); empty keeps history in memory only")
	historyRetention := fs.Int("history-retention", historystore.DefaultRetention,
		"observations retained per asset (minimum 1)")
	observeFile := fs.String("observe", "",
		"path to asset list file (one CODE-ISSUER per line) for scheduled observation")
	observeInterval := fs.Duration("observe-interval", 6*time.Hour,
		"interval between scheduled scans of the asset list")
	trustedProxies := fs.String("trusted-proxies", "",
		"comma-separated CIDRs of trusted reverse proxies whose X-Forwarded-For headers are trusted")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	if *historyRetention < 1 {
		return usagef("serve: -history-retention must be at least 1, got %d", *historyRetention)
	}

	// The server is where a list configuration matters most: every scan it
	// serves consults the same configured lists, attributed the same way, and
	// records them in the observation history like any other evidence.
	srv := api.NewServer(log)
	if *trustedProxies != "" {
		proxies, err := api.ParseTrustedProxies(*trustedProxies)
		if err != nil {
			return fmt.Errorf("serve: trusted-proxies: %w", err)
		}
		srv.TrustedProxies = proxies
	}
	srv.Scanner = newScanner(assetLists(), cache())
	historyStore, err := openHistory(*historyPath, *historyRetention)
	if err != nil {
		return err
	}
	srv.History = historyStore
	defer func() { _ = historyStore.Close() }()

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start scheduled observation if configured.
	if *observeFile != "" {
		assets, err := parseAssetListFile(*observeFile)
		if err != nil {
			return fmt.Errorf("serve: observe: %w", err)
		}
		if len(assets) == 0 {
			log.Info("serve: observe: asset list is empty, no scheduled scans")
		} else {
			log.Info("serve: observe: scheduled scans enabled", "assets", len(assets), "interval", *observeInterval)
			go runScheduledObservation(ctx, log, srv.Scanner, srv.History, assets, *observeInterval)
		}
	}

	errChan := make(chan error, 1)
	go func() {
		log.Info("assay listening", "addr", *addr, "history", *historyPath)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Info("shutting down server gracefully")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("serve: shutdown: %w", err)
		}
		return nil
	}
}

// parseAssetListFile reads a file with one CODE-ISSUER per line and returns
// the parsed assets. Empty lines and lines starting with # are ignored.
func parseAssetListFile(path string) ([]mechanics.Asset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read asset list: %w", err)
	}
	var assets []mechanics.Asset
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		asset, err := scan.ParseAsset(line)
		if err != nil {
			return nil, fmt.Errorf("parse asset %q: %w", line, err)
		}
		assets = append(assets, asset)
	}
	return assets, nil
}

// runScheduledObservation runs periodic scans of the given assets and appends
// observations to the history store. It runs until the context is cancelled.
func runScheduledObservation(ctx context.Context, log *slog.Logger, scanner *scan.Scanner, history *historystore.Store, assets []mechanics.Asset, interval time.Duration) {
	// Run an initial scan immediately.
	scanAll(ctx, log, scanner, history, assets)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scanAll(ctx, log, scanner, history, assets)
		}
	}
}

// scanAll scans all assets sequentially and appends observations to history.
func scanAll(ctx context.Context, log *slog.Logger, scanner *scan.Scanner, history *historystore.Store, assets []mechanics.Asset) {
	for _, asset := range assets {
		select {
		case <-ctx.Done():
			return
		default:
		}

		scanCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		report, err := scanner.Scan(scanCtx, asset)
		cancel()

		if err != nil {
			log.Error("scheduled scan failed", "asset", asset.String(), "err", err)
			continue
		}

		// Record observation in history store.
		if history != nil {
			obs := temporal.ObservationFromReport(report)
			if err := history.Append(obs); err != nil {
				log.Error("scheduled scan: history append failed", "asset", asset.String(), "err", err)
			}
		}

		log.Info("scheduled scan completed", "asset", asset.String(), "severity", report.Severity.String())
	}
}
