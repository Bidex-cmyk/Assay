package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/api"
)

// TestRequestIDBoundAndSanitised covers the rule the middleware enforces on a
// caller-supplied X-Request-Id: a value is only echoed when it is 1–128 bytes
// of [A-Za-z0-9._:-]. Anything else is ignored and a fresh identifier is
// generated, so a caller cannot bloat the logs or choose a value that is not a
// usable grep key.
func TestRequestIDBoundAndSanitised(t *testing.T) {
	handler := api.NewServer(nil).Handler()

	long128 := strings.Repeat("a", 128)
	long129 := long128 + "x"

	cases := []struct {
		name   string
		in     string
		echoed bool
	}{
		{name: "empty", in: "", echoed: false},
		{name: "valid", in: "corr-test-123", echoed: true},
		{name: "valid charset", in: "Abc.123_x:y-z", echoed: true},
		{name: "128 bytes", in: long128, echoed: true},
		{name: "129 bytes", in: long129, echoed: false},
		{name: "control character", in: "abc\ndef", echoed: false},
		{name: "nul byte", in: "abc\x00def", echoed: false},
		{name: "space", in: "abc def", echoed: false},
		{name: "non-ASCII", in: "abcé", echoed: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			if tc.in != "" {
				req.Header.Set("X-Request-Id", tc.in)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			got := rec.Header().Get("X-Request-Id")
			if got == "" {
				t.Fatal("no X-Request-Id on the response")
			}
			if tc.echoed {
				if got != tc.in {
					t.Fatalf("echoed %q, want the caller's %q", got, tc.in)
				}
				return
			}
			if got == tc.in {
				t.Fatalf("echoed unacceptable identifier %q verbatim", got)
			}
			if len(got) != 32 || strings.Trim(got, "0123456789abcdef") != "" {
				t.Fatalf("generated identifier %q is not 16 random bytes hex-encoded", got)
			}
		})
	}
}
