package assetlist_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/assetlist"
)

// The caching contract for SEP-0042 lists (issue #408). Lists are large, change
// rarely and are fetched on every scan that configures them, so they are cached
// — but a cached claim must keep the time it was actually fetched, not the time
// a cache served it.

// serveCountingList serves a valid list body and counts requests, so a test can
// assert the cache engaged rather than assume it.
func serveCountingList(t *testing.T, body string, status int) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestCacheHitKeepsOriginalFetchTime is the acceptance case: a second fetch
// inside the TTL is served without a request, and its FetchedAt is the first
// fetch's instant. Re-stamping it would make the report claim a freshness the
// list does not have.
func TestCacheHitKeepsOriginalFetchTime(t *testing.T) {
	srv, hits := serveCountingList(t, string(readFixture(t)), http.StatusOK)

	now := time.Date(2026, 9, 27, 17, 34, 0, 0, time.UTC)
	c := assetlist.NewWithOptions(assetlist.Options{
		TTL: assetlist.DefaultTTL,
		Now: func() time.Time { return now },
	})

	first, err := c.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("requests after first fetch = %d, want 1", got)
	}
	if !first.FetchedAt.Equal(now) {
		t.Fatalf("first FetchedAt = %v, want %v", first.FetchedAt, now)
	}

	// A hit well inside the TTL: no request, and the ORIGINAL fetch time.
	now = now.Add(assetlist.DefaultTTL / 2)
	second, err := c.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Errorf("requests after cached fetch = %d, want 1 (the list should be served from cache)", got)
	}
	if !second.FetchedAt.Equal(first.FetchedAt) {
		t.Errorf("cached FetchedAt = %v, want the original fetch time %v",
			second.FetchedAt, first.FetchedAt)
	}
	if second.Name != first.Name || len(second.Assets) != len(first.Assets) {
		t.Error("a cached fetch returned a different list")
	}
}

// TestCacheHitReturnsACopy: a caller that edits the returned list must not
// change what the next hit sees.
func TestCacheHitReturnsACopy(t *testing.T) {
	srv, _ := serveCountingList(t, string(readFixture(t)), http.StatusOK)
	c := assetlist.NewWithOptions(assetlist.Options{TTL: assetlist.DefaultTTL})

	first, err := c.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	if len(first.Assets) == 0 {
		t.Fatal("fixture has no assets")
	}
	original := first.Name
	first.Name = "edited by a caller"
	first.Assets = nil

	second, err := c.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if second.Name != original {
		t.Errorf("cached list was mutated through the returned pointer: name = %q", second.Name)
	}
	if len(second.Assets) == 0 {
		t.Error("cached list lost its assets through the returned pointer")
	}
}

// TestExpiredListIsRefetched: expiry means re-fetch, never "assume the previous
// answer still holds". A newly added asset must appear once the TTL passes.
func TestExpiredListIsRefetched(t *testing.T) {
	srv, hits := serveCountingList(t, string(readFixture(t)), http.StatusOK)

	now := time.Date(2026, 9, 27, 17, 34, 0, 0, time.UTC)
	c := assetlist.NewWithOptions(assetlist.Options{
		TTL: assetlist.DefaultTTL,
		Now: func() time.Time { return now },
	})

	if _, err := c.Fetch(context.Background(), srv.URL); err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	now = now.Add(assetlist.DefaultTTL)
	fresh, err := c.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch after expiry: %v", err)
	}
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Fatalf("requests after expiry = %d, want 2", got)
	}
	if !fresh.FetchedAt.Equal(now) {
		t.Errorf("refetched FetchedAt = %v, want the new fetch time %v", fresh.FetchedAt, now)
	}
}

// TestFailedFetchIsNotCached: caching an outage would keep serving it after the
// source recovered. The next lookup must ask again.
func TestListFailureIsNotCached(t *testing.T) {
	var hits int32
	var status atomic.Int32
	status.Store(http.StatusServiceUnavailable)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		if status.Load() != http.StatusOK {
			w.WriteHeader(int(status.Load()))
			return
		}
		_, _ = w.Write(readFixture(t))
	}))
	t.Cleanup(srv.Close)

	c := assetlist.New()
	if _, err := c.Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("a 503 was reported as a usable list")
	}

	status.Store(http.StatusOK)
	list, err := c.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("Fetch after recovery: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("requests = %d, want the failed attempt and the retry (2)", got)
	}
	if list.Name == "" {
		t.Error("recovered fetch did not return the list")
	}
}

// TestZeroTTLDisablesCaching: TTL 0 is how "caching is off" is expressed, and
// it must be the same code path, just always missing.
func TestZeroTTLDisablesListCaching(t *testing.T) {
	srv, hits := serveCountingList(t, string(readFixture(t)), http.StatusOK)
	c := assetlist.NewWithOptions(assetlist.Options{TTL: 0})

	for i := 0; i < 3; i++ {
		if _, err := c.Fetch(context.Background(), srv.URL); err != nil {
			t.Fatalf("Fetch %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(hits); got != 3 {
		t.Fatalf("requests with caching disabled = %d, want 3", got)
	}
}
