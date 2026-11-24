package api_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/use-assay/assay/internal/stellarexpert"
)

// countingExpert wraps the shared StellarExpert stub and counts the curated
// lookups that actually reach the source, so a test can tell a cache hit from
// a re-fetch.
type countingExpert struct {
	inner     expertStub
	directory atomic.Int32
	blocklist atomic.Int32
}

func (c *countingExpert) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.Contains(r.URL.Path, "/directory/blocked-domains/"):
		c.blocklist.Add(1)
	case strings.Contains(r.URL.Path, "/explorer/directory/"):
		c.directory.Add(1)
	}
	c.inner.ServeHTTP(w, r)
}

func (c *countingExpert) total() int { return int(c.directory.Load() + c.blocklist.Load()) }

// newMaxAgeServer is the logging harness with a caching StellarExpert client
// pointed at a counting stub. The cache TTL is long, so any re-fetch in a test
// is caused by max_age_secs and not by the TTL expiring.
func newMaxAgeServer(t *testing.T) (http.Handler, *countingExpert) {
	t.Helper()
	ls := newLogServer(t)
	stub := &countingExpert{}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	ls.srv.Scanner.Expert = stellarexpert.NewWithOptions(srv.URL, stellarexpert.Options{
		DirectoryTTL: time.Hour,
		BlocklistTTL: time.Hour,
	})
	return ls.handler, stub
}

func scanWith(t *testing.T, h http.Handler, extra string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scan?asset="+url.QueryEscape(logTestAsset)+extra, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scan%s: status = %d, want 200; body %s", extra, rec.Code, rec.Body.String())
	}
}

// TestScanMaxAgeSecsZeroForcesRefetch is the contract of max_age_secs: the
// default reuses a cached reputation answer, and max_age_secs=0 means "do not
// reuse" and asks the source again.
func TestScanMaxAgeSecsZeroForcesRefetch(t *testing.T) {
	h, stub := newMaxAgeServer(t)

	scanWith(t, h, "") // populates the cache
	first := stub.total()
	if first == 0 {
		t.Fatal("first scan made no StellarExpert request; the stub is not exercised")
	}

	scanWith(t, h, "") // default: reuses the cache
	if got := stub.total(); got != first {
		t.Fatalf("default scan re-fetched: requests = %d, want %d (cache reuse)", got, first)
	}

	scanWith(t, h, "&max_age_secs=0")
	if got := stub.total(); got != 2*first {
		t.Fatalf("max_age_secs=0 requests = %d, want %d (every lookup re-fetched)", got, 2*first)
	}
}

// TestScanMaxAgeSecsLargeBoundReusesCache shows a bound the cached answer
// still satisfies does not cause a re-fetch, and that the max_age alias is
// honoured the same way as max_age_secs.
func TestScanMaxAgeSecsLargeBoundReusesCache(t *testing.T) {
	h, stub := newMaxAgeServer(t)

	scanWith(t, h, "")
	first := stub.total()

	scanWith(t, h, "&max_age_secs=3600")
	scanWith(t, h, "&max_age=3600")
	if got := stub.total(); got != first {
		t.Fatalf("scans within the bound re-fetched: requests = %d, want %d", got, first)
	}

	scanWith(t, h, "&max_age=0")
	if got := stub.total(); got != 2*first {
		t.Fatalf("max_age=0 alias requests = %d, want %d", got, 2*first)
	}
}
