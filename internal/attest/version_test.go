package attest_test

import (
	"errors"
	"testing"

	"github.com/use-assay/assay/internal/attest"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		name      string
		v1        string
		v2        string
		wantCmp   int
		expectErr bool
	}{
		// Standard semver equality and order
		{"equal_simple", "v1.0.0", "v1.0.0", 0, false},
		{"major_greater", "v2.0.0", "v1.0.0", 1, false},
		{"major_less", "v1.0.0", "v2.0.0", -1, false},
		{"minor_greater", "v1.2.0", "v1.1.0", 1, false},
		{"minor_less", "v1.1.0", "v1.2.0", -1, false},
		{"patch_greater", "v1.0.2", "v1.0.1", 1, false},
		{"patch_less", "v1.0.1", "v1.0.2", -1, false},

		// Pre-release ordering (Issue #581)
		{"prerelease_less_than_normal", "v1.2.3-rc1", "v1.2.3", -1, false},
		{"normal_greater_than_prerelease", "v1.2.3", "v1.2.3-rc1", 1, false},
		{"prerelease_patch_greater_than_older_normal", "v1.2.3-rc1", "v1.2.1", 1, false},
		{"prerelease_numeric_comparison", "v1.0.0-beta.2", "v1.0.0-beta.11", -1, false},
		{"prerelease_alphanumeric_comparison", "v1.0.0-alpha", "v1.0.0-beta", -1, false},
		{"prerelease_num_less_than_alpha", "v1.0.0-1", "v1.0.0-alpha", -1, false},
		{"prerelease_length_comparison", "v1.0.0-alpha", "v1.0.0-alpha.1", -1, false},
		{"prerelease_equal", "v1.2.3-rc.1", "v1.2.3-rc.1", 0, false},

		// Build metadata (ignored for precedence)
		{"build_metadata_ignored_equal", "v1.2.3+20261123", "v1.2.3+20261124", 0, false},
		{"build_metadata_ignored_vs_none", "v1.2.3+build.1", "v1.2.3", 0, false},
		{"prerelease_with_build_metadata", "v1.2.3-rc1+build1", "v1.2.3-rc1+build2", 0, false},
		{"prerelease_with_build_vs_prerelease", "v1.2.3-rc1+build1", "v1.2.3-rc1", 0, false},

		// Missing 'v' prefix is malformed/invalid
		{"missing_v_prefix_v1", "1.2.3", "v1.2.3", 0, true},
		{"missing_v_prefix_v2", "v1.2.3", "1.2.3", 0, true},
		{"missing_v_prefix_both", "1.2.3", "1.2.4", 0, true},

		// Garbage and malformed strings
		{"garbage_v1", "garbage", "v1.0.0", 0, true},
		{"garbage_v2", "v1.0.0", "garbage", 0, true},
		{"devel_v1", "devel", "v1.0.0", 0, true},
		{"devel_v2", "v1.0.0", "devel", 0, true},
		{"incomplete_v1", "v1.2", "v1.2.0", 0, true},
		{"four_parts", "v1.2.3.4", "v1.2.3", 0, true},
		{"leading_zero_major", "v01.2.3", "v1.2.3", 0, true},
		{"leading_zero_minor", "v1.02.3", "v1.2.3", 0, true},
		{"leading_zero_patch", "v1.2.03", "v1.2.3", 0, true},
		{"leading_zero_prerelease_num", "v1.2.3-01", "v1.2.3-1", 0, true},
		{"empty_prerelease", "v1.2.3-", "v1.2.3", 0, true},
		{"empty_build", "v1.2.3+", "v1.2.3", 0, true},
		{"empty_string", "", "v1.0.0", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmp, err := attest.CompareVersions(tc.v1, tc.v2)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("CompareVersions(%q, %q) expected error, got cmp=%d", tc.v1, tc.v2, cmp)
				}
				if !errors.Is(err, attest.ErrInvalidVersion) {
					t.Fatalf("expected ErrInvalidVersion, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("CompareVersions(%q, %q) unexpected error: %v", tc.v1, tc.v2, err)
			}
			if cmp != tc.wantCmp {
				t.Fatalf("CompareVersions(%q, %q) = %d, want %d", tc.v1, tc.v2, cmp, tc.wantCmp)
			}
		})
	}
}

func TestVerifyVersionTable(t *testing.T) {
	tests := []struct {
		name       string
		recorded   string
		min        string
		wantStatus attest.ProvenanceStatus
		wantErr    error
	}{
		{"valid_exact", "v1.2.3", "v1.2.3", attest.ProvenanceValid, nil},
		{"valid_higher_patch", "v1.2.4", "v1.2.3", attest.ProvenanceValid, nil},
		{"valid_higher_minor", "v1.3.0", "v1.2.3", attest.ProvenanceValid, nil},
		{"valid_higher_major", "v2.0.0", "v1.2.3", attest.ProvenanceValid, nil},
		{"valid_with_build", "v1.2.3+build.42", "v1.2.3", attest.ProvenanceValid, nil},

		// Pre-release checks
		{"downgrade_prerelease_below_release", "v1.2.3-rc1", "v1.2.3", attest.ProvenanceInvalid, attest.ErrScannerDowngrade},
		{"valid_prerelease_above_older_patch", "v1.2.3-rc1", "v1.2.2", attest.ProvenanceValid, nil},

		// Unknown provenance cases (empty and devel)
		{"empty_recorded_version", "", "v1.0.0", attest.ProvenanceUnknown, attest.ErrUnknownProvenance},
		{"whitespace_recorded_version", "   ", "v1.0.0", attest.ProvenanceUnknown, attest.ErrUnknownProvenance},
		{"devel_recorded_version", "devel", "v1.0.0", attest.ProvenanceUnknown, attest.ErrUnknownProvenance},
		{"devel_recorded_version_trimmed", "  devel  ", "v1.0.0", attest.ProvenanceUnknown, attest.ErrUnknownProvenance},

		// Malformed / invalid recorded versions
		{"garbage_recorded", "garbage", "v1.0.0", attest.ProvenanceInvalid, attest.ErrInvalidVersion},
		{"missing_v_prefix", "1.2.3", "v1.0.0", attest.ProvenanceInvalid, attest.ErrInvalidVersion},
		{"two_parts", "v1.2", "v1.0.0", attest.ProvenanceInvalid, attest.ErrInvalidVersion},
		{"four_parts", "v1.2.3.4", "v1.0.0", attest.ProvenanceInvalid, attest.ErrInvalidVersion},
		{"leading_zero", "v1.02.0", "v1.0.0", attest.ProvenanceInvalid, attest.ErrInvalidVersion},

		// Malformed minimum version
		{"garbage_min_version", "v1.0.0", "garbage", attest.ProvenanceInvalid, attest.ErrInvalidVersion},
		{"missing_v_min_version", "v1.0.0", "1.0.0", attest.ProvenanceInvalid, attest.ErrInvalidVersion},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, err := attest.VerifyVersion(tc.recorded, tc.min)
			if status != tc.wantStatus {
				t.Fatalf("VerifyVersion(%q, %q) status = %v, want %v", tc.recorded, tc.min, status, tc.wantStatus)
			}
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("VerifyVersion(%q, %q) expected error %v, got nil", tc.recorded, tc.min, tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("VerifyVersion(%q, %q) error = %v, want %v", tc.recorded, tc.min, err, tc.wantErr)
				}
			} else if err != nil {
				t.Fatalf("VerifyVersion(%q, %q) unexpected error: %v", tc.recorded, tc.min, err)
			}
		})
	}
}
