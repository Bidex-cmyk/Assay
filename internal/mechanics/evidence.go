package mechanics

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/use-assay/assay/internal/horizon"
)

// horizonBaseURL returns the base URL of the Horizon instance that answered
// this scan, honoring s.HorizonURL when populated, then s.Network, defaulting
// to pubnet.
func (s *Subject) horizonBaseURL() string {
	if s != nil && s.HorizonURL != "" {
		return strings.TrimRight(s.HorizonURL, "/")
	}
	if s != nil && s.Network == horizon.TestNet {
		return horizon.DefaultTestnetURL
	}
	return horizon.DefaultURL
}

// horizonAssetURL returns the public Horizon URL backing an asset claim, so the
// reader can re-fetch exactly what Assay read.
func (s *Subject) horizonAssetURL(a Asset) string {
	q := url.Values{}
	q.Set("asset_code", a.Code)
	q.Set("asset_issuer", a.Issuer)
	return s.horizonBaseURL() + "/assets?" + q.Encode()
}

// horizonAccountURL returns the public Horizon URL for the issuer or holder
// account, so a reader can re-fetch the authorization flags or trustlines themselves.
//
// Horizon publishes the issuer's flags twice: on the asset record and on the
// account. Verified live on 2026-09-25 across six assets, both endpoints carry
// the identical four field names and agreed in every case. That agreement is
// what makes a disagreement worth reporting rather than averaging away.
func (s *Subject) horizonAccountURL(account string) string {
	return s.horizonBaseURL() + "/accounts/" + url.PathEscape(account)
}

// flagSummary renders the issuer flag set in Horizon's own vocabulary.
func flagSummary(f horizon.Flags) string {
	return fmt.Sprintf(
		"auth_required=%t auth_revocable=%t auth_immutable=%t auth_clawback_enabled=%t",
		f.AuthRequired, f.AuthRevocable, f.AuthImmutable, f.AuthClawbackEnabled,
	)
}
