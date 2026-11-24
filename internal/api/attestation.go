package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/use-assay/assay/internal/attest"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/scan"
)

// attestationBody is the response for GET /api/v1/attestation. When Attestable
// is true the caller has the exact arguments of an on-chain attest() call.
// When false, Reason and ErrorKind explain what prevents attestation.
type attestationBody struct {
	Attestable   bool     `json:"attestable"`
	Severity     uint32   `json:"severity"`
	SeverityName string   `json:"severity_name"`
	Flags        uint32   `json:"flags"`
	Mechanics    []string `json:"mechanics"`
	Checks       []string `json:"checks,omitempty"`
	Network      string   `json:"network,omitempty"`
	EvidenceHash string   `json:"evidence_hash"`
	ScannedAt    string   `json:"scanned_at"`
	Preimage     string   `json:"preimage,omitempty"`
	Reason       string   `json:"reason,omitempty"`
	ErrorKind    string   `json:"error_kind,omitempty"`
}

func (s *Server) handleAttestation(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("asset")
	if raw == "" {
		writeJSON(w, http.StatusBadRequest, apiErr(codeMissingParam, "missing ?asset=CODE-ISSUER"))
		return
	}

	asset, err := scan.ParseAsset(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiErr(codeInvalidAsset, err.Error()))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	rep, scanErr := s.Scanner.ScanWithHolder(ctx, asset, "")
	if scanErr != nil {
		if errors.Is(scanErr, horizon.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, apiErr(codeAssetNotFound, "asset not found on the ledger"))
			return
		}
		s.loggerFrom(r.Context()).Error("attestation scan failed", "asset", asset.String(), "err", scanErr)
		writeJSON(w, http.StatusBadGateway, apiErr(codeUpstreamUnavail, "scan failed: "+scanErr.Error()))
		return
	}

	params, err := attest.FromReport(rep)
	if err != nil {
		writeJSON(w, http.StatusOK, attestationBody{
			Attestable: false,
			Reason:     err.Error(),
			ErrorKind:  attestErrorKind(err),
		})
		return
	}

	writeJSON(w, http.StatusOK, attestationBody{
		Attestable:   true,
		Severity:     params.Severity,
		SeverityName: params.SeverityName,
		Flags:        params.Flags,
		Mechanics:    params.Mechanics,
		Checks:       params.Checks,
		Network:      params.Network,
		EvidenceHash: params.EvidenceHash,
		ScannedAt:    params.ScannedAt,
		Preimage:     params.Preimage,
	})
}

// attestErrorKind maps an attestation refusal error to a machine-readable kind
// string so the UI can render an appropriate explanation without parsing the
// error message.
func attestErrorKind(err error) string {
	switch {
	case errors.Is(err, attest.ErrUndetermined):
		return "undetermined"
	case errors.Is(err, attest.ErrUnevaluated):
		return "unevaluated"
	case errors.Is(err, attest.ErrStale):
		return "stale"
	case errors.Is(err, attest.ErrInconsistent):
		return "inconsistent"
	case errors.Is(err, attest.ErrPartialCheckSet):
		return "partial_check_set"
	default:
		return "scan_failed"
	}
}
