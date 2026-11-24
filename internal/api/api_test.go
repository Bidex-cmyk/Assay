package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/api"
)

func newTestServer() http.Handler {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return api.NewServer(log).Handler()
}

// TestScanRejectsBadInput covers the paths that fail before any network call,
// so the test stays hermetic.
func TestScanRejectsBadInput(t *testing.T) {
	h := newTestServer()

	for _, tc := range []struct {
		name  string
		query string
		code  string
	}{
		{"missing asset", "/api/v1/scan", "missing_param"},
		{"empty asset", "/api/v1/scan?asset=", "missing_param"},
		{"not an asset", "/api/v1/scan?asset=hello", "invalid_asset"},
		{"bad issuer", "/api/v1/scan?asset=USDC-NOPE", "invalid_asset"},
		{"invalid max_age_secs", "/api/v1/scan?asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&max_age_secs=notanumber", "invalid_param"},
		{"negative max_age_secs", "/api/v1/scan?asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN&max_age_secs=-10", "invalid_param"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.query, nil))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			var body struct {
				Error string `json:"error"`
				Code  string `json:"code"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body.Error == "" {
				t.Error("error body was empty; a caller must be able to tell why it failed")
			}
			if body.Code != tc.code {
				t.Errorf("code = %q, want %q", body.Code, tc.code)
			}
		})
	}
}

// TestScanNativeAssetIsExplicit400 pins the documented answer for the
// network's native asset: an understood input, refused with 400 and a message
// naming the ledger fact — no issuer, no authorization flags — rather than a
// parse error. docs/api.md documents both the status and the wording.
func TestScanNativeAssetIsExplicit400(t *testing.T) {
	h := newTestServer()

	for _, query := range []string{
		"/api/v1/scan?asset=native",
		"/api/v1/scan?asset=XLM",
		"/api/v1/scan?asset=xlm",
	} {
		t.Run(query, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, query, nil))

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			for _, want := range []string{
				"native asset has no issuer and no authorization flags",
				"cannot be scanned or attested",
			} {
				if !strings.Contains(body.Error, want) {
					t.Errorf("error = %q, want it to say %q", body.Error, want)
				}
			}
		})
	}
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestUIServed(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	// The UI must present severity and accountability as separate things. If
	// someone collapses them into one score, this fails loudly.
	for _, want := range []string{"Severity — issuer capability", "Accountability — who stands behind it"} {
		if !strings.Contains(body, want) {
			t.Errorf("UI missing %q", want)
		}
	}
}

func TestUnknownPathIs404(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestUnknownAPIPathIsJSON404 pins the API contract for a mistyped path: an
// API client decodes error bodies as JSON, so an unknown /api/ path must not
// fall through to the UI's http.NotFound plain text.
func TestUnknownAPIPathIsJSON404(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/unknown", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error == "" {
		t.Error("error body was empty; an API client must be able to tell why it failed")
	}
	if body.Code != "not_found" {
		t.Errorf("code = %q, want not_found", body.Code)
	}
}

// TestWrongMethodIsJSON405 pins the answer to a method an API path does not
// serve: JSON, with Allow naming the method it does.
func TestWrongMethodIsJSON405(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/scan", nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != http.MethodGet {
		t.Errorf("Allow = %q, want %q", got, http.MethodGet)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Code != "method_not_allowed" {
		t.Errorf("code = %q, want method_not_allowed", body.Code)
	}
}

// TestNonAPIPathKeepsPlainText404 holds the line between the API and the UI:
// only /api/ responses are JSON, so the UI's existing 404 is untouched.
func TestNonAPIPathKeepsPlainText404(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/nope", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", got)
	}
	if !strings.Contains(rec.Body.String(), "404 page not found") {
		t.Errorf("body = %q, want the standard plain-text 404", rec.Body.String())
	}
}

func TestScanUndeterminedHeaderContract(t *testing.T) {
	// A scan on a nonexistent or unreachable asset returns undetermined or fails;
	// we can verify the header contract is set properly on responses.
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scan?asset=UNKNOWN-GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA", nil))
	if rec.Code == http.StatusOK {
		if got := rec.Header().Get("X-Assay-Undetermined"); got != "true" && got != "false" {
			t.Errorf("X-Assay-Undetermined header missing or invalid: %q", got)
		}
	}
}

func TestCORSHeadersOnAPIRoutes(t *testing.T) {
	h := newTestServer()

	for _, tc := range []struct {
		name   string
		path   string
		method string
		want   int
	}{
		{"GET scan CORS", "/api/v1/scan", http.MethodGet, http.StatusBadRequest},
		{"OPTIONS preflight scan", "/api/v1/scan", http.MethodOptions, http.StatusNoContent},
		{"OPTIONS preflight history", "/api/v1/history", http.MethodOptions, http.StatusNoContent},
		{"OPTIONS preflight exposure", "/api/v1/exposure", http.MethodOptions, http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
				t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
			}
		})
	}
}

func TestCORSNotSetOnNonAPIRoutes(t *testing.T) {
	rec := httptest.NewRecorder()
	newTestServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin set on UI route: %q", got)
	}
}

func TestErrorBodyHasCode(t *testing.T) {
	h := newTestServer()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scan", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	var body struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Code == "" {
		t.Error("error body missing code field; API contract requires a stable code")
	}
}

// TestScanRateLimitOff pins the default: a nil ScanLimiter means no rate
// limit is applied, so the handler is reachable without restriction.
func TestScanRateLimitOff(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := api.NewServer(log)
	// ScanLimiter is nil by default — no limit installed.
	h := srv.Handler()

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/scan", nil)
		req.RemoteAddr = "203.0.113.1:4000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: got 429 with no limiter configured", i+1)
		}
	}
}

// TestScanRateLimited pins the per-client rate-limit criterion: a client that
// exhausts its burst is refused with 429 and a Retry-After header, while a
// different client's bucket remains untouched (#429).
func TestScanRateLimited(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := api.NewServer(log)
	// Burst of 2 with a near-frozen refill so the third request from the same
	// address is refused without sleeping.
	srv.ScanLimiter = api.NewRateLimiter(2, 0.000001)
	h := srv.Handler()

	scan := func(remoteAddr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/scan?asset=USDC-GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN", nil)
		req.RemoteAddr = remoteAddr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// First two requests from the same client spend the burst.
	for i := 1; i <= 2; i++ {
		rec := scan("203.0.113.1:4000")
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: unexpected 429 within burst", i)
		}
	}

	// Third request from the same client is refused.
	rec := scan("203.0.113.1:4000")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 without Retry-After: a refused caller is told to stop, not when to return")
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode 429 body: %v", err)
	}
	if body.Code != "rate_limited" {
		t.Errorf("429 code = %q, want rate_limited", body.Code)
	}

	// A different client still has its own full burst.
	rec = scan("203.0.113.2:4000")
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("other client: got 429, want independent burst")
	}
}
