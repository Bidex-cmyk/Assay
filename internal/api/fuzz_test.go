package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// assertFuzzInvariants checks the response invariants documented in openapi.yaml:
//   - Content-Type is application/json
//   - Body decodes as valid JSON
//   - HTTP status is in the caller-supplied allowed set
func assertFuzzInvariants(t *testing.T, rec *httptest.ResponseRecorder, allowed map[int]bool) {
	t.Helper()
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body, _ := io.ReadAll(rec.Body)
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Errorf("body is not valid JSON (status %d): %v\nbody: %s", rec.Code, err, body)
	}
	if !allowed[rec.Code] {
		t.Errorf("status %d not in documented set %v", rec.Code, allowed)
	}
}

// fuzzRequest builds a GET request for target, skipping inputs that cannot be
// expressed as an HTTP request line at all (spaces, control characters):
// httptest.NewRequest panics on those, and they never reach a handler in
// production because the HTTP server rejects them first.
func fuzzRequest(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil || strings.ContainsAny(target, " \t\r\n") {
		t.Skip("not a well-formed request target")
	}
	req.RequestURI = target
	return req
}

// FuzzScanQuery sends arbitrary query strings to /api/v1/scan and verifies that
// every response is JSON with a status documented in openapi.yaml for this
// route (200, 400, 404, 502).
//
// The server is wired to newTestServer() which rejects most invalid inputs as
// 400 before any upstream fetch, keeping the test hermetic for the common fuzz
// paths. The seed corpus covers the cases api_test.go already enumerates.
func FuzzScanQuery(f *testing.F) {
	f.Add("asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN")
	f.Add("asset=")
	f.Add("asset=hello")
	f.Add("asset=USDC-NOPE")
	f.Add("asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&max_age_secs=notanumber")
	f.Add("asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&max_age_secs=-10")
	f.Add("asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&holder=GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H")
	f.Add("asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&holder=notanaddress")
	f.Add("asset=native")
	f.Add("asset=XLM")
	f.Add("")
	f.Add("asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&unknown_param=value")

	// Documented statuses from openapi.yaml: 200, 400, 404, 502.
	// The server may also return 502 when the stub upstreams are unreachable,
	// which newTestServer does not stub — that is acceptable since the invariant
	// (JSON body, documented status) still holds.
	allowed := map[int]bool{
		http.StatusOK:         true,
		http.StatusBadRequest: true,
		http.StatusNotFound:   true,
		http.StatusBadGateway: true,
	}

	f.Fuzz(func(t *testing.T, query string) {
		h := newTestServer()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, fuzzRequest(t, "/api/v1/scan?"+query))
		assertFuzzInvariants(t, rec, allowed)
	})
}

// FuzzHistoryQuery sends arbitrary query strings to /api/v1/history and
// verifies the documented contract: every response is JSON with status 200 or
// 400. History never scans, so the stub-free server is fully hermetic here.
func FuzzHistoryQuery(f *testing.F) {
	f.Add("asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN")
	f.Add("asset=")
	f.Add("asset=hello")
	f.Add("asset=USDC-NOPE")
	f.Add("asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&limit=10")
	f.Add("asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&limit=0")
	f.Add("asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&limit=notanumber")
	f.Add("asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&limit=9999999")
	f.Add("asset=native")
	f.Add("")

	// Documented statuses from openapi.yaml: 200, 400.
	allowed := map[int]bool{
		http.StatusOK:         true,
		http.StatusBadRequest: true,
	}

	f.Fuzz(func(t *testing.T, query string) {
		h := newTestServer()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, fuzzRequest(t, "/api/v1/history?"+query))
		assertFuzzInvariants(t, rec, allowed)
	})
}

// FuzzExposureQuery sends arbitrary query strings to /api/v1/exposure and
// verifies the documented contract: every response is JSON with status 200,
// 400, 404, 429, or 502. It reuses newExposureServer from exposure_test.go so
// the upstream stubs are the same ones the non-fuzz exposure tests rely on.
func FuzzExposureQuery(f *testing.F) {
	f.Add("account=" + exposureAccount)
	f.Add("account=")
	f.Add("account=NOPE")
	f.Add("account=" + exposureAccount + "&limit=5")
	f.Add("account=" + exposureAccount + "&limit=0")
	f.Add("account=" + exposureAccount + "&cursor=0")
	f.Add("account=" + exposureAccount + "&limit=notanumber")
	f.Add("account=" + exposureAccount + "&limit=-1")
	f.Add("")

	// Documented statuses from openapi.yaml: 200, 400, 404, 429, 502.
	allowed := map[int]bool{
		http.StatusOK:              true,
		http.StatusBadRequest:      true,
		http.StatusNotFound:        true,
		http.StatusTooManyRequests: true,
		http.StatusBadGateway:      true,
	}

	f.Fuzz(func(t *testing.T, query string) {
		h := newExposureServer(t, &exposureHorizonStub{trustlines: []string{"USDC"}})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, fuzzRequest(t, "/api/v1/exposure?"+query))
		assertFuzzInvariants(t, rec, allowed)
	})
}
