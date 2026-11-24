package scan_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
)

// holderIssuer is a syntactically valid ed25519 public key used as a holder
// account. It is never validated by the ledger in these tests.
const holderIssuer = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"

// stubConfig selects which sources fail in the matrix below. Every field is a
// switch over a stub server, so the test never touches a network.
type stubConfig struct {
	homeDomain          string
	horizonAssetFail    bool
	horizonAccountFail  bool
	tomlFail            bool
	directoryFail       bool
	blocklistFail       bool
	holderTrustline     bool
	holderTrustlineFail bool
}

// newStubScanner wires a Scanner to stub Horizon, StellarExpert and stellar.toml
// servers according to cfg.
func newStubScanner(t *testing.T, cfg stubConfig) *scan.Scanner {
	t.Helper()

	horizon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Latest-Ledger", "55678123")
		switch {
		case r.URL.Path == "/assets":
			if cfg.horizonAssetFail {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"_embedded": map[string]any{
					"records": []map[string]any{{
						"asset_type":   "credit_alphanum4",
						"asset_code":   "USDC",
						"asset_issuer": scanIssuer,
						"flags":        horizonFlagsStub,
					}},
				},
			})
		case strings.HasPrefix(r.URL.Path, "/accounts/"):
			id := strings.TrimPrefix(r.URL.Path, "/accounts/")
			if id == scanIssuer {
				if cfg.horizonAccountFail {
					http.Error(w, "boom", http.StatusInternalServerError)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"account_id":  scanIssuer,
					"home_domain": cfg.homeDomain,
					"flags":       horizonFlagsStub,
				})
				return
			}
			if cfg.holderTrustlineFail {
				http.Error(w, "boom", http.StatusInternalServerError)
				return
			}
			balances := []map[string]any{}
			if cfg.holderTrustline {
				balances = append(balances, map[string]any{
					"asset_type":          "credit_alphanum4",
					"asset_code":          "USDC",
					"asset_issuer":        scanIssuer,
					"is_authorized":       true,
					"is_clawback_enabled": false,
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"account_id": id, "balances": balances})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(horizon.Close)

	expert := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/explorer/directory/blocked-domains/"):
			if cfg.blocklistFail {
				http.Error(w, "boom", http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"domain":"` + cfg.homeDomain + `","blocked":false}`))
		case strings.HasPrefix(r.URL.Path, "/explorer/directory/"):
			if cfg.directoryFail {
				http.Error(w, "boom", http.StatusServiceUnavailable)
				return
			}
			// The directory answers an unlisted address 200 with an empty object.
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(expert.Close)

	toml := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.tomlFail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("[[CURRENCIES]]\ncode=\"USDC\"\nissuer=\"" + scanIssuer + "\"\n"))
	}))
	t.Cleanup(toml.Close)

	sc := scan.New()
	sc.Horizon.BaseURL = horizon.URL
	sc.Expert.BaseURL = expert.URL
	sc.Toml.HTTP.Transport = &singleHostTransport{host: strings.TrimPrefix(toml.URL, "http://")}
	return sc
}

// TestScannerSubjectErrorMatrix is the acceptance test for #77. It drives the
// real Subject assembly over injected stub sources and asserts, for every
// combination of outcomes, which failures are fatal (Horizon) and which are
// recorded and survived (every consumed source).
func TestScannerSubjectErrorMatrix(t *testing.T) {
	cases := []struct {
		name      string
		cfg       stubConfig
		wantFatal bool
		check     func(t *testing.T, sub *mechanics.Subject)
	}{
		{
			name: "all sources succeed",
			cfg:  stubConfig{homeDomain: scanHomeDom},
			check: func(t *testing.T, sub *mechanics.Subject) {
				if sub.Stat == nil || sub.Issuer == nil {
					t.Fatal("ledger sources did not populate the subject")
				}
				if sub.Toml == nil {
					t.Error("toml did not resolve")
				}
				if sub.TomlErr != "" {
					t.Errorf("TomlErr = %q, want empty", sub.TomlErr)
				}
				if sub.Blocked == nil {
					t.Error("blocklist did not resolve")
				}
				if sub.DirectoryErr != "" || sub.BlockedErr != "" {
					t.Errorf("unexpected consumed-source errors: directory=%q blocked=%q",
						sub.DirectoryErr, sub.BlockedErr)
				}
			},
		},
		{
			name:      "horizon asset fails",
			cfg:       stubConfig{homeDomain: scanHomeDom, horizonAssetFail: true},
			wantFatal: true,
		},
		{
			name:      "horizon account fails",
			cfg:       stubConfig{homeDomain: scanHomeDom, horizonAccountFail: true},
			wantFatal: true,
		},
		{
			name: "toml fails",
			cfg:  stubConfig{homeDomain: scanHomeDom, tomlFail: true},
			check: func(t *testing.T, sub *mechanics.Subject) {
				if sub.Toml != nil {
					t.Error("Toml is non-nil after a failed fetch")
				}
				if sub.TomlErr == "" {
					t.Error("TomlErr is empty after a failed fetch")
				}
				if sub.TomlRefused {
					t.Error("an ordinary fetch failure was marked as a host-policy refusal")
				}
				// A consumed failure must not stop the other sources.
				if sub.DirectoryErr != "" || sub.BlockedErr != "" {
					t.Errorf("a toml failure also broke another source: directory=%q blocked=%q",
						sub.DirectoryErr, sub.BlockedErr)
				}
			},
		},
		{
			name: "directory fails",
			cfg:  stubConfig{homeDomain: scanHomeDom, directoryFail: true},
			check: func(t *testing.T, sub *mechanics.Subject) {
				if sub.DirectoryErr == "" {
					t.Error("DirectoryErr is empty after a failed fetch")
				}
				if sub.Directory != nil {
					t.Error("Directory is non-nil after a failed fetch")
				}
				if sub.TomlErr != "" {
					t.Errorf("a directory failure also broke the toml: %q", sub.TomlErr)
				}
			},
		},
		{
			name: "blocklist fails",
			cfg:  stubConfig{homeDomain: scanHomeDom, blocklistFail: true},
			check: func(t *testing.T, sub *mechanics.Subject) {
				if sub.BlockedErr == "" {
					t.Error("BlockedErr is empty after a failed fetch")
				}
				if sub.Blocked != nil {
					t.Error("Blocked is non-nil after a failed fetch")
				}
			},
		},
		{
			name: "no home_domain",
			cfg:  stubConfig{homeDomain: ""},
			check: func(t *testing.T, sub *mechanics.Subject) {
				// toml and blocklist are not attempted at all, and that must be
				// distinct from their having failed: every field stays zero.
				if sub.Toml != nil || sub.TomlErr != "" || sub.TomlRefused {
					t.Errorf("toml fields are populated without a home_domain: %+v / %q / %v",
						sub.Toml, sub.TomlErr, sub.TomlRefused)
				}
				if sub.TomlURL != "" {
					t.Errorf("TomlURL = %q, want empty without a home_domain", sub.TomlURL)
				}
				if sub.Blocked != nil || sub.BlockedErr != "" || sub.BlockedURL != "" {
					t.Errorf("blocklist fields are populated without a home_domain: %+v / %q / %q",
						sub.Blocked, sub.BlockedErr, sub.BlockedURL)
				}
				// The directory is independent of home_domain and is still read.
				if sub.DirectoryErr != "" {
					t.Errorf("directory should still be attempted without a home_domain: %q", sub.DirectoryErr)
				}
			},
		},
		{
			name: "several consumed sources fail at once",
			cfg: stubConfig{
				homeDomain:    scanHomeDom,
				tomlFail:      true,
				directoryFail: true,
				blocklistFail: true,
			},
			check: func(t *testing.T, sub *mechanics.Subject) {
				if sub.TomlErr == "" {
					t.Error("TomlErr is empty")
				}
				if sub.DirectoryErr == "" {
					t.Error("DirectoryErr is empty")
				}
				if sub.BlockedErr == "" {
					t.Error("BlockedErr is empty")
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := newStubScanner(t, tc.cfg)
			sub, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer))

			if tc.wantFatal {
				if err == nil {
					t.Fatalf("expected a fatal error; got subject %+v", sub)
				}
				if sub != nil {
					t.Fatalf("a fatal source must return no subject, got %+v", sub)
				}
				return
			}
			if err != nil {
				t.Fatalf("Subject: %v", err)
			}
			if sub == nil {
				t.Fatal("Subject returned nil without an error")
			}
			if tc.check != nil {
				tc.check(t, sub)
			}
		})
	}
}

// The SEP-23 test vectors: a published base account and two muxed addresses
// built from it (ids 0 and 420). They are taken from the protocol
// documentation rather than generated here, so the decoder is checked against
// bytes other implementations already agree on.
const (
	muxedBaseAccount = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
	muxedIDZero      = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ"
	muxedID420       = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAABUTGI4"
)

func TestValidateHolder(t *testing.T) {
	if err := scan.ValidateHolder(holderIssuer); err != nil {
		t.Errorf("ValidateHolder(valid) = %v", err)
	}
	// An M… holder is accepted: it resolves to the same G… account the lookup
	// is made against, so refusing it would refuse a real exchange address
	// whose exposure is fully answerable (issue #410).
	for _, m := range []string{muxedIDZero, muxedID420} {
		if err := scan.ValidateHolder(m); err != nil {
			t.Errorf("ValidateHolder(%q) = %v, want nil", m, err)
		}
	}
	for _, bad := range []string{
		"",
		"not-a-key",
		"gbrpyhil2ci3fnq4bxlfmndlfjunpu2hy3zmfshonuceoasw7qc7ox2h",
		// An M… address whose checksum no longer matches must be refused, not
		// resolved onto whichever account the remaining bytes spell.
		muxedID420[:len(muxedID420)-1] + "5",
	} {
		if err := scan.ValidateHolder(bad); !errors.Is(err, scan.ErrBadHolder) {
			t.Errorf("ValidateHolder(%q) error = %v, want ErrBadHolder", bad, err)
		}
	}
}

// TestParseHolderResolvesMuxed pins the M… → G… resolution the trustline check
// depends on: the base account is the one SEP-23 says the address refers to,
// and the multiplexing id is decoded from the payload rather than guessed.
func TestParseHolderResolvesMuxed(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		id   uint64
	}{
		{"id zero", muxedIDZero, 0},
		{"id 420", muxedID420, 420},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, id, muxed, err := scan.ParseHolder(tc.in)
			if err != nil {
				t.Fatalf("ParseHolder(%q): %v", tc.in, err)
			}
			if !muxed {
				t.Error("muxed = false for an M… address")
			}
			if base != muxedBaseAccount {
				t.Errorf("base = %q, want %q", base, muxedBaseAccount)
			}
			if id != tc.id {
				t.Errorf("id = %d, want %d", id, tc.id)
			}
		})
	}

	t.Run("plain G is passed through", func(t *testing.T) {
		base, id, muxed, err := scan.ParseHolder(muxedBaseAccount)
		if err != nil {
			t.Fatalf("ParseHolder: %v", err)
		}
		if muxed || id != 0 || base != muxedBaseAccount {
			t.Errorf("base = %q, id = %d, muxed = %t", base, id, muxed)
		}
	})
}

func TestScanReturnsReport(t *testing.T) {
	sc := newStubScanner(t, stubConfig{homeDomain: scanHomeDom})
	rep, err := sc.Scan(context.Background(), mustParse(t, "USDC-"+scanIssuer))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rep.Asset.Code != "USDC" || rep.Asset.Issuer != scanIssuer {
		t.Fatalf("report asset = %v", rep.Asset)
	}
	if rep.ScannedAt.IsZero() {
		t.Error("report ScannedAt is zero")
	}
}

func TestSubjectWithHolder(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		sc := newStubScanner(t, stubConfig{homeDomain: scanHomeDom, holderTrustline: true})
		sub, err := sc.SubjectWithHolder(context.Background(), mustParse(t, "USDC-"+scanIssuer), holderIssuer)
		if err != nil {
			t.Fatalf("SubjectWithHolder: %v", err)
		}
		if sub.Holder != holderIssuer {
			t.Errorf("Holder = %q, want %q", sub.Holder, holderIssuer)
		}
		if sub.HolderTrustline == nil {
			t.Fatal("HolderTrustline is nil for a holder that holds the asset")
		}
		if sub.HolderTrustlineErr != "" {
			t.Errorf("HolderTrustlineErr = %q, want empty", sub.HolderTrustlineErr)
		}
		if sub.HolderFetchedAt.IsZero() {
			t.Error("HolderFetchedAt is zero on success")
		}
	})

	t.Run("not held", func(t *testing.T) {
		sc := newStubScanner(t, stubConfig{homeDomain: scanHomeDom})
		sub, err := sc.SubjectWithHolder(context.Background(), mustParse(t, "USDC-"+scanIssuer), holderIssuer)
		if err != nil {
			t.Fatalf("SubjectWithHolder: %v", err)
		}
		// "Not listed" is an answer, not an outage: no error, but a completion
		// time and no trustline.
		if sub.HolderTrustline != nil {
			t.Error("HolderTrustline is non-nil for a holder that does not hold the asset")
		}
		if sub.HolderTrustlineErr != "" {
			t.Errorf("a missing trustline was recorded as an error: %q", sub.HolderTrustlineErr)
		}
		if sub.HolderFetchedAt.IsZero() {
			t.Error("a missing trustline should still record a completion time")
		}
	})

	t.Run("upstream fails", func(t *testing.T) {
		sc := newStubScanner(t, stubConfig{homeDomain: scanHomeDom, holderTrustlineFail: true})
		sub, err := sc.SubjectWithHolder(context.Background(), mustParse(t, "USDC-"+scanIssuer), holderIssuer)
		if err != nil {
			t.Fatalf("SubjectWithHolder: %v", err)
		}
		if sub.HolderTrustlineErr == "" {
			t.Error("HolderTrustlineErr is empty after a failed fetch")
		}
		if sub.HolderAttemptedAt.IsZero() {
			t.Error("a failed holder fetch should record an attempt time")
		}
	})

	t.Run("muxed holder resolves to its base account", func(t *testing.T) {
		sc := newStubScanner(t, stubConfig{homeDomain: scanHomeDom, holderTrustline: true})
		sub, err := sc.SubjectWithHolder(context.Background(), mustParse(t, "USDC-"+scanIssuer), muxedID420)
		if err != nil {
			t.Fatalf("SubjectWithHolder: %v", err)
		}
		// The lookup is made against the ledger account; the muxed address is
		// kept so the report can say the resolution happened.
		if sub.Holder != muxedBaseAccount {
			t.Errorf("Holder = %q, want the base account %q", sub.Holder, muxedBaseAccount)
		}
		if sub.HolderMuxed != muxedID420 {
			t.Errorf("HolderMuxed = %q, want %q", sub.HolderMuxed, muxedID420)
		}
		if sub.HolderMuxedID != 420 {
			t.Errorf("HolderMuxedID = %d, want 420", sub.HolderMuxedID)
		}
		if sub.HolderTrustline == nil {
			t.Fatal("HolderTrustline is nil for a muxed holder that holds the asset")
		}
	})

	t.Run("malformed muxed holder is refused", func(t *testing.T) {
		sc := newStubScanner(t, stubConfig{homeDomain: scanHomeDom})
		_, err := sc.SubjectWithHolder(context.Background(), mustParse(t, "USDC-"+scanIssuer),
			muxedID420[:len(muxedID420)-1]+"5")
		if !errors.Is(err, scan.ErrBadHolder) {
			t.Fatalf("error = %v, want ErrBadHolder", err)
		}
	})

	t.Run("empty holder is identical to Subject", func(t *testing.T) {
		sc := newStubScanner(t, stubConfig{homeDomain: scanHomeDom})
		sub, err := sc.SubjectWithHolder(context.Background(), mustParse(t, "USDC-"+scanIssuer), "")
		if err != nil {
			t.Fatalf("SubjectWithHolder: %v", err)
		}
		if sub.Holder != "" || sub.HolderTrustline != nil {
			t.Errorf("empty holder should not add holder state: %+v", sub)
		}
	})
}

func TestScanWithHolderAddsTrustlineCheck(t *testing.T) {
	sc := newStubScanner(t, stubConfig{homeDomain: scanHomeDom, holderTrustline: true})
	rep, err := sc.ScanWithHolder(context.Background(), mustParse(t, "USDC-"+scanIssuer), holderIssuer)
	if err != nil {
		t.Fatalf("ScanWithHolder: %v", err)
	}
	var found bool
	for _, id := range rep.CheckSet {
		if id == "trustline" {
			found = true
		}
	}
	if !found {
		t.Fatalf("trustline check missing from check set %v", rep.CheckSet)
	}
}

// TestScanEvidenceCarriesLedgerSequence verifies issue #402:
// Horizon evidence records carry the ledger sequence reported by Horizon (from headers or root)
// as metadata outside the preimage, and it serializes into JSON evidence.
func TestScanEvidenceCarriesLedgerSequence(t *testing.T) {
	sc := newStubScanner(t, stubConfig{homeDomain: scanHomeDom, holderTrustline: true})
	rep, err := sc.ScanWithHolder(context.Background(), mustParse(t, "USDC-"+scanIssuer), holderIssuer)
	if err != nil {
		t.Fatalf("ScanWithHolder: %v", err)
	}

	var horizonEvidenceCount int
	for _, ev := range rep.Evidence {
		if strings.HasPrefix(ev.Source, "horizon") {
			horizonEvidenceCount++
			if ev.LatestLedger != 55678123 {
				t.Errorf("evidence %s has LatestLedger = %d, want 55678123", ev.Source, ev.LatestLedger)
			}
			if ev.LedgerSequence != 55678123 {
				t.Errorf("evidence %s has LedgerSequence = %d, want 55678123", ev.Source, ev.LedgerSequence)
			}

			// Verify JSON marshaling includes both field names
			data, err := json.Marshal(ev)
			if err != nil {
				t.Fatalf("json.Marshal(ev): %v", err)
			}
			jsonStr := string(data)
			if !strings.Contains(jsonStr, `"latest_ledger":55678123`) {
				t.Errorf("JSON evidence missing latest_ledger: %s", jsonStr)
			}
			if !strings.Contains(jsonStr, `"ledger_sequence":55678123`) {
				t.Errorf("JSON evidence missing ledger_sequence: %s", jsonStr)
			}
		} else {
			// Non-Horizon evidence should not carry ledger sequence
			if ev.LatestLedger != 0 || ev.LedgerSequence != 0 {
				t.Errorf("non-horizon evidence %s has non-zero ledger sequence: %d / %d",
					ev.Source, ev.LatestLedger, ev.LedgerSequence)
			}
		}
	}

	if horizonEvidenceCount == 0 {
		t.Fatal("expected at least one horizon evidence in scan report")
	}
}
