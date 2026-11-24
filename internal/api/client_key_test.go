package api_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/use-assay/assay/internal/api"
)

func TestParseTrustedProxies(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{"empty string", "", 0, false},
		{"whitespace", "   ", 0, false},
		{"single CIDR", "10.0.0.0/8", 1, false},
		{"bare IPv4", "127.0.0.1", 1, false},
		{"bare IPv6", "::1", 1, false},
		{"mixed list", "127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.1.1, ::1", 5, false},
		{"invalid CIDR", "not-a-cidr", 0, true},
		{"invalid IP", "999.999.999.999", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nets, err := api.ParseTrustedProxies(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseTrustedProxies(%q) err = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
			if len(nets) != tc.wantLen {
				t.Fatalf("len = %d, want %d", len(nets), tc.wantLen)
			}
		})
	}
}

// TestClientKeyUntrustedPeerCannotPickBucket ensures that when an immediate
// peer is untrusted (or no trusted proxies are configured), headers like
// X-Forwarded-For are never consulted.
func TestClientKeyUntrustedPeerCannotPickBucket(t *testing.T) {
	trusted, err := api.ParseTrustedProxies("10.0.0.0/8, 127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		trusted    bool
		remoteAddr string
		xff        string
		wantKey    string
	}{
		{
			name:       "no trusted proxies configured, ignores XFF",
			trusted:    false,
			remoteAddr: "203.0.113.10:12345",
			xff:        "198.51.100.1, 8.8.8.8",
			wantKey:    "203.0.113.10",
		},
		{
			name:       "immediate peer untrusted, ignores XFF",
			trusted:    true,
			remoteAddr: "203.0.113.10:12345",
			xff:        "198.51.100.1, 10.0.0.1",
			wantKey:    "203.0.113.10",
		},
		{
			name:       "untrusted peer with port in remoteAddr",
			trusted:    true,
			remoteAddr: "198.51.100.5:54321",
			xff:        "1.1.1.1",
			wantKey:    "198.51.100.5",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}

			var nets = trusted
			if !tc.trusted {
				nets = nil
			}

			key := api.ClientKey(req, nets)
			if key != tc.wantKey {
				t.Fatalf("ClientKey = %q, want %q", key, tc.wantKey)
			}
		})
	}
}

// TestClientKeyTrustedProxyChains validates multi-hop XFF traversal from the right,
// IPv6 addresses, ports in XFF, and malformed entries.
func TestClientKeyTrustedProxyChains(t *testing.T) {
	trustedNets, err := api.ParseTrustedProxies("10.0.0.0/8, 172.16.0.0/12, 127.0.0.1/32, fd00::/8")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		remoteAddr string
		xff        []string
		wantKey    string
	}{
		{
			name:       "single trusted proxy, single client",
			remoteAddr: "10.0.0.1:4000",
			xff:        []string{"203.0.113.50"},
			wantKey:    "203.0.113.50",
		},
		{
			name:       "multi-hop XFF: client -> proxy1 -> proxy2 -> server",
			remoteAddr: "10.0.0.2:4000",
			xff:        []string{"203.0.113.50, 10.0.0.1"},
			wantKey:    "203.0.113.50",
		},
		{
			name:       "multi-hop XFF with separate headers",
			remoteAddr: "10.0.0.2:4000",
			xff:        []string{"203.0.113.50", "172.16.0.1", "10.0.0.1"},
			wantKey:    "203.0.113.50",
		},
		{
			name:       "attacker spoofing header through trusted proxy",
			remoteAddr: "10.0.0.2:4000",
			// Attacker is 198.51.100.99 pretending to be 1.1.1.1.
			// Proxy appends attacker IP 198.51.100.99, then next proxy appends 10.0.0.1.
			xff:     []string{"1.1.1.1, 198.51.100.99, 10.0.0.1"},
			wantKey: "198.51.100.99",
		},
		{
			name:       "IPv6 client through trusted IPv4 proxy",
			remoteAddr: "10.0.0.1:4000",
			xff:        []string{"2001:db8::1234"},
			wantKey:    "2001:db8::1234",
		},
		{
			name:       "IPv6 client through trusted IPv6 proxy",
			remoteAddr: "[fd00::1]:4000",
			xff:        []string{"2001:db8::abcd, fd00::2"},
			wantKey:    "2001:db8::abcd",
		},
		{
			name:       "XFF with port numbers",
			remoteAddr: "10.0.0.1:4000",
			xff:        []string{"203.0.113.50:8080, 10.0.0.2:8443"},
			wantKey:    "203.0.113.50",
		},
		{
			name:       "malformed entry is treated as untrusted address",
			remoteAddr: "10.0.0.1:4000",
			xff:        []string{"203.0.113.50, malformed-ip, 10.0.0.2"},
			wantKey:    "malformed-ip",
		},
		{
			name:       "all hops in XFF are trusted",
			remoteAddr: "10.0.0.2:4000",
			xff:        []string{"10.0.0.1, 172.16.0.5"},
			wantKey:    "10.0.0.1",
		},
		{
			name:       "empty XFF header falls back to peerHost",
			remoteAddr: "10.0.0.1:4000",
			xff:        []string{""},
			wantKey:    "10.0.0.1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.RemoteAddr = tc.remoteAddr
			for _, h := range tc.xff {
				req.Header.Add("X-Forwarded-For", h)
			}

			key := api.ClientKey(req, trustedNets)
			if key != tc.wantKey {
				t.Fatalf("ClientKey = %q, want %q", key, tc.wantKey)
			}
		})
	}
}

// TestRateLimitWithTrustedProxyEndToEnd exercises the rate limiter behind a
// configured trusted proxy, proving:
// 1. Two clients forwarding through the same trusted proxy get separate buckets.
// 2. An untrusted client cannot rotate buckets by spoofing X-Forwarded-For.
func TestRateLimitWithTrustedProxyEndToEnd(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := api.NewServer(log)
	trusted, err := api.ParseTrustedProxies("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	srv.TrustedProxies = trusted
	// Limit: 2 burst, zero refill
	srv.ExposureLimiter = api.NewRateLimiter(2, 0.0000001)

	h := srv.Handler()

	// Two requests from client A through proxy 10.0.0.1
	reqA := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/exposure?account="+exposureAccount, nil)
		req.RemoteAddr = "10.0.0.1:45678"
		req.Header.Set("X-Forwarded-For", "203.0.113.1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec1 := reqA()
	if rec1.Code == http.StatusTooManyRequests {
		t.Fatalf("client A request 1 was rate limited unexpectedly: %d", rec1.Code)
	}
	rec2 := reqA()
	if rec2.Code == http.StatusTooManyRequests {
		t.Fatalf("client A request 2 was rate limited unexpectedly: %d", rec2.Code)
	}
	// Third request from client A must be rate limited (429)
	rec3 := reqA()
	if rec3.Code != http.StatusTooManyRequests {
		t.Fatalf("client A request 3 status = %d, want 429", rec3.Code)
	}

	// Client B through the same proxy 10.0.0.1 must still have its burst available!
	reqB := httptest.NewRequest(http.MethodGet, "/api/v1/exposure?account="+exposureAccount, nil)
	reqB.RemoteAddr = "10.0.0.1:45678"
	reqB.Header.Set("X-Forwarded-For", "203.0.113.2")
	recB := httptest.NewRecorder()
	h.ServeHTTP(recB, reqB)
	if recB.Code == http.StatusTooManyRequests {
		t.Fatalf("client B should not be rate limited by client A's requests: %d", recB.Code)
	}

	// Now verify an untrusted client (not in 10.0.0.0/8) cannot bypass rate limit:
	// Untrusted peer 198.51.100.5 exhausts burst.
	reqUntrusted := func(spoofedXFF string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/exposure?account="+exposureAccount, nil)
		req.RemoteAddr = "198.51.100.5:12345"
		if spoofedXFF != "" {
			req.Header.Set("X-Forwarded-For", spoofedXFF)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	reqUntrusted("1.1.1.1")
	reqUntrusted("2.2.2.2")
	// Third request with yet another spoofed IP must still be 429!
	recUntrusted3 := reqUntrusted("3.3.3.3")
	if recUntrusted3.Code != http.StatusTooManyRequests {
		t.Fatalf("untrusted peer was able to bypass rate limit with spoofed header: %d", recUntrusted3.Code)
	}
}
