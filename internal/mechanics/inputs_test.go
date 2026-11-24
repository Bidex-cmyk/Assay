package mechanics_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/assetlist"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/sep1"
	"github.com/use-assay/assay/internal/stellarexpert"
)

// The input-declaration harness (#413).
//
// Each check declares the Subject fields it reads (Check.Inputs). Severity
// derives only from capability checks, and that property is easier to keep when
// every check's inputs are explicit; the list also documents which sources a
// check depends on, which is what decides undetermined.
//
// The declaration is only worth having if it can go stale loudly. So the harness
// exercises the opposite direction: for every field a check does NOT declare, it
// builds one subject variant with that field populated and one with it zeroed,
// holding every declared field fixed. If the finding changes, the check read an
// undeclared field, and the test names the field. The harness is itself tested
// (TestInputHarnessCatchesAnUndeclaredRead), because a detector that never fires
// proves nothing.

// harnessIssuer and harnessHolder are valid Stellar ed25519 account ID shapes
// used only as identifiers; they carry no ledger state.
const (
	harnessIssuer = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
	harnessHolder = "GBWXEAB6QPNZWDGR7JPBPIXQJYGYQOQ7QIUOTFJ5XT2Z6TB4T7SMYB6"
	// harnessMuxed is the SEP-23 vector for a base key with multiplexing id 0;
	// only the string is used here, by the trustline check.
	harnessMuxed = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ"
)

// testAt is one fixed instant, so findings built from these subjects are
// byte-identical across runs.
var testAt = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

// richSubject is a Subject with every source present and successful. It is the
// "all fields populated" side of the harness; the degraded variant below covers
// the branches that only run when a source is absent.
func richSubject() *mechanics.Subject {
	return &mechanics.Subject{
		Asset: mechanics.Asset{Code: "USDC", Issuer: harnessIssuer},

		Stat: &horizon.AssetStat{
			AssetType:    "credit_alphanum4",
			AssetCode:    "USDC",
			AssetIssuer:  harnessIssuer,
			ContractID:   "CCW67TSZV3SSS2HXMBQ5JFGCKJNXKZM7UQUWUZPUTHXSTZLEO7SJMI75",
			Flags:        horizon.Flags{AuthRequired: true, AuthRevocable: true, AuthClawbackEnabled: true},
			LatestLedger: 100,
		},
		StatFetchedAt: testAt,
		StatLedger:    100,

		Issuer: &horizon.Account{
			AccountID:    harnessIssuer,
			HomeDomain:   "example.org",
			Flags:        horizon.Flags{AuthRequired: true, AuthRevocable: true, AuthClawbackEnabled: true},
			LatestLedger: 100,
		},
		IssuerFetchedAt: testAt,
		IssuerLedger:    100,

		Toml: &sep1.Doc{
			Currencies: []sep1.Currency{
				{Code: "USDC", Issuer: harnessIssuer, Name: "USD Coin", Status: "live"},
			},
			Documentation:     sep1.Documentation{OrgName: "Example Org", OrgURL: "https://example.org"},
			NetworkPassphrase: string(horizon.PublicNet),
			URL:               "https://example.org/.well-known/stellar.toml",
			FetchedAt:         testAt,
		},
		TomlURL:         "https://example.org/.well-known/stellar.toml",
		TomlAttemptedAt: testAt,
		TomlLinked: &sep1.LinkedResolution{
			Attempted:  1,
			Claimed:    true,
			ClaimedURL: "https://example.org/usdc.toml",
			Docs: []sep1.LinkedDoc{{
				URL: "https://example.org/usdc.toml",
				Doc: &sep1.Doc{
					Currencies: []sep1.Currency{{Code: "USDC", Issuer: harnessIssuer}},
					URL:        "https://example.org/usdc.toml",
					FetchedAt:  testAt,
				},
			}},
		},

		Directory: &stellarexpert.DirectoryEntry{
			Address: harnessIssuer,
			Name:    "Example",
			Domain:  "example.org",
			Tags:    []string{"issuer", "malicious", "unmapped-tag"},
		},
		DirectoryURL:         "https://api.stellar.expert/explorer/directory/" + harnessIssuer,
		DirectoryFetchedAt:   testAt,
		DirectoryAttemptedAt: testAt,

		Blocked:            &stellarexpert.BlockedDomain{Domain: "example.org", Blocked: true},
		BlockedURL:         "https://api.stellar.expert/explorer/directory/blocked-domains/example.org",
		BlockedFetchedAt:   testAt,
		BlockedAttemptedAt: testAt,

		ExpertAsset: &stellarexpert.Asset{
			Asset:      "USDC-" + harnessIssuer,
			Code:       "USDC",
			Issuer:     harnessIssuer,
			Supply:     "1000000",
			Trustlines: stellarexpert.TrustlineCounts{Total: 10, Authorized: 9, Funded: 8},
			Rating:     stellarexpert.AssetRating{Age: 1, Activity: 2, Trustlines: 3, Liquidity: 4, Volume7d: 5, Interop: 6, Average: 7},
		},
		ExpertAssetURL:         "https://api.stellar.expert/explorer/public/asset/USDC-" + harnessIssuer,
		ExpertAssetFetchedAt:   testAt,
		ExpertAssetAttemptedAt: testAt,

		AssetLists: []mechanics.AssetListSignal{{
			Name:        "Example List",
			Provider:    "Example",
			URL:         "https://list.example/list.json",
			Version:     "1.0",
			Network:     "public",
			Entry:       &assetlist.Asset{Code: "USDC", Issuer: harnessIssuer, Name: "USD Coin", Org: "Example", Domain: "example.org"},
			Listed:      true,
			FetchedAt:   testAt,
			AttemptedAt: testAt,
		}},

		Holder:            harnessHolder,
		HolderMuxed:       harnessMuxed,
		HolderMuxedID:     0,
		HolderTrustline:   &horizon.TrustlineBalance{AssetCode: "USDC", AssetIssuer: harnessIssuer, IsAuthorized: true, LatestLedger: 100},
		HolderFetchedAt:   testAt,
		HolderAttemptedAt: testAt,
		HolderLedger:      100,

		ScannedAt:  testAt,
		FetchedAt:  testAt,
		Network:    horizon.PublicNet,
		HorizonURL: horizon.DefaultURL,
	}
}

// degradedSubject is the other end of the range: the ledger sources are absent
// and every best-effort source failed. Checks that handle an outage read error
// fields and attempt times that the rich subject leaves unused, so exercising
// both directions is what makes the harness cover the check's branches rather
// than only its happy path.
func degradedSubject() *mechanics.Subject {
	return &mechanics.Subject{
		Asset: mechanics.Asset{Code: "USDC", Issuer: harnessIssuer},

		TomlURL:         "https://example.org/.well-known/stellar.toml",
		TomlErr:         "status 404",
		TomlAttemptedAt: testAt,

		DirectoryURL:         "https://api.stellar.expert/explorer/directory/" + harnessIssuer,
		DirectoryErr:         "stellarexpert: get: status 429",
		DirectoryAttemptedAt: testAt,

		BlockedURL:         "https://api.stellar.expert/explorer/directory/blocked-domains/example.org",
		BlockedErr:         "stellarexpert: get: status 429",
		BlockedAttemptedAt: testAt,

		ExpertAssetURL:         "https://api.stellar.expert/explorer/public/asset/USDC-" + harnessIssuer,
		ExpertAssetErr:         "stellarexpert: get: status 429",
		ExpertAssetAttemptedAt: testAt,

		Holder:             harnessHolder,
		HolderTrustlineErr: "horizon: get: status 429",
		HolderAttemptedAt:  testAt,

		ScannedAt:  testAt,
		FetchedAt:  testAt,
		Network:    horizon.PublicNet,
		HorizonURL: horizon.DefaultURL,
	}
}

// subjectFieldNames returns every top-level Subject field, sorted so failures
// read in a stable order.
func subjectFieldNames(t *testing.T) []string {
	t.Helper()
	typ := reflect.TypeOf(mechanics.Subject{})
	names := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			t.Fatalf("Subject field %q is unexported; the harness cannot vary it", f.Name)
		}
		names = append(names, f.Name)
	}
	sort.Strings(names)
	return names
}

// findingFingerprint runs one check and renders its result in a stable form.
// A check that errors is represented by the error, which is itself an observable
// change: returning a different error because an undeclared field moved is the
// same defect as returning different evidence for it.
func findingFingerprint(t *testing.T, c mechanics.Check, s *mechanics.Subject) string {
	t.Helper()
	f, err := c.Run(context.Background(), s)
	if err != nil {
		return "error: " + err.Error()
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("%s: marshal finding: %v", c.ID(), err)
	}
	return string(b)
}

// withSubjectField returns a shallow copy of s with one top-level field replaced.
// A shallow copy is enough: the check only reads the Subject it is handed, and
// the replacement never mutates a shared struct.
func withSubjectField(s *mechanics.Subject, field string, v reflect.Value) *mechanics.Subject {
	clone := *s
	reflect.ValueOf(&clone).Elem().FieldByName(field).Set(v)
	return &clone
}

func subjectFieldValue(s *mechanics.Subject, field string) reflect.Value {
	return reflect.ValueOf(s).Elem().FieldByName(field)
}

// undeclaredReads reports, for one check, the Subject fields it demonstrably
// reads without declaring them in Inputs().
//
// The method is behavioural rather than static: Go has no read barrier to
// observe a field access, so the harness varies each undeclared field — both to
// a populated value and to its zero value — and requires the finding to stay
// byte-identical. If it changes, the check consulted a field it did not declare.
// Both a populated and a degraded base are used so a check that only reads the
// field on its outage path is caught too.
func undeclaredReads(t *testing.T, c mechanics.Check) []string {
	t.Helper()
	declared := make(map[string]bool, len(c.Inputs()))
	for _, name := range c.Inputs() {
		declared[name] = true
	}

	rich := richSubject()
	bases := []struct {
		name string
		sub  *mechanics.Subject
	}{
		{"populated", rich},
		{"degraded", degradedSubject()},
	}

	var violations []string
	for _, base := range bases {
		want := findingFingerprint(t, c, base.sub)
		for _, field := range subjectFieldNames(t) {
			if declared[field] {
				continue
			}
			fieldType, ok := reflect.TypeOf(mechanics.Subject{}).FieldByName(field)
			if !ok {
				t.Fatalf("Subject field %q vanished", field)
			}
			variants := []struct {
				label string
				value reflect.Value
			}{
				{"zeroed", reflect.New(fieldType.Type).Elem()},
				{"populated", subjectFieldValue(rich, field)},
			}
			for _, variant := range variants {
				got := findingFingerprint(t, c, withSubjectField(base.sub, field, variant.value))
				if got != want {
					violations = append(violations, fmt.Sprintf("%s (%s base, field %s)",
						field, base.name, variant.label))
					break
				}
			}
		}
	}
	sort.Strings(violations)
	return violations
}

// TestChecksDeclareTheirInputs is the acceptance test for #413: every check
// declares the Subject fields it reads, the declarations name real fields, and
// no check reads a field it did not declare.
func TestChecksDeclareTheirInputs(t *testing.T) {
	fields := make(map[string]bool)
	for _, name := range subjectFieldNames(t) {
		fields[name] = true
	}

	checks := []mechanics.Check{
		mechanics.CapabilityCheck{},
		mechanics.MutabilityCheck{},
		mechanics.DomainCheck{},
		mechanics.ReputationCheck{},
		mechanics.TrustlineCheck{},
	}

	for _, c := range checks {
		t.Run(c.ID(), func(t *testing.T) {
			declared := c.Inputs()
			if len(declared) == 0 {
				t.Fatalf("%s declares no inputs; every check reads at least the asset it classifies", c.ID())
			}
			seen := make(map[string]bool, len(declared))
			for _, name := range declared {
				if !fields[name] {
					t.Errorf("%s declares %q, which is not a mechanics.Subject field", c.ID(), name)
				}
				if seen[name] {
					t.Errorf("%s declares %q more than once", c.ID(), name)
				}
				seen[name] = true
			}

			for _, read := range undeclaredReads(t, c) {
				t.Errorf("%s reads a Subject field it does not declare in Inputs(): %s", c.ID(), read)
			}
		})
	}
}

// leakyCheck reads a field it does not declare. It exists only to prove the
// harness fires: a detector that cannot fail is decoration, not a test.
type leakyCheck struct {
	declared []string
}

func (leakyCheck) ID() string       { return "leaky" }
func (leakyCheck) Describe() string { return "reads Holder without declaring it" }
func (c leakyCheck) Inputs() []string {
	return c.declared
}
func (leakyCheck) Run(_ context.Context, s *mechanics.Subject) (mechanics.Finding, error) {
	return mechanics.Finding{
		Check:     "leaky",
		Title:     "leaky",
		Reasoning: "holder " + s.Holder,
		Evidence:  []mechanics.Evidence{},
	}, nil
}

// TestInputHarnessCatchesAnUndeclaredRead verifies both halves of the harness's
// own claim: an undeclared read is reported, and declaring the same field
// silences it (no false positive).
func TestInputHarnessCatchesAnUndeclaredRead(t *testing.T) {
	violations := undeclaredReads(t, leakyCheck{})
	found := false
	for _, v := range violations {
		if strings.HasPrefix(v, "Holder (") {
			found = true
		}
	}
	if !found {
		t.Fatalf("harness did not catch the undeclared Holder read: %v", violations)
	}

	if violations := undeclaredReads(t, leakyCheck{declared: []string{"Holder"}}); len(violations) != 0 {
		t.Fatalf("declaring Holder did not silence the harness: %v", violations)
	}
}
