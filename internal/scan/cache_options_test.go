package scan_test

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/use-assay/assay/internal/scan"
)

// TestCacheOptionsRefetchBothSources is the acceptance test for the CLI's
// -no-cache and -cache-*-ttl 0 flags: both must make every scan re-fetch both
// curated StellarExpert sources instead of reusing an answer.
func TestCacheOptionsRefetchBothSources(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts scan.Options
	}{
		{"no-cache", scan.Options{NoReputationCache: true}},
		{"zero TTLs", scan.Options{ReputationDirectoryTTL: 0, ReputationBlocklistTTL: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := newFakeSources(t)

			var directoryRequests, blocklistRequests int64
			fs.expert.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasPrefix(r.URL.Path, "/explorer/directory/blocked-domains/"):
					atomic.AddInt64(&blocklistRequests, 1)
					_, _ = w.Write([]byte(`{"domain":"` + scanHomeDom + `","blocked":false}`))
				case strings.HasPrefix(r.URL.Path, "/explorer/directory/"):
					atomic.AddInt64(&directoryRequests, 1)
					_, _ = w.Write([]byte(`{"address":"` + scanIssuer + `","name":"Centre","domain":"centre.test"}`))
				default:
					http.NotFound(w, r)
				}
			})

			sc := scan.NewWithOptions(tc.opts)
			sc.Horizon.BaseURL = fs.horizon.URL
			sc.Expert.BaseURL = fs.expert.URL
			sc.Toml.HTTP.Transport = &singleHostTransport{host: strings.TrimPrefix(fs.toml.URL, "http://")}

			for i := 0; i < 2; i++ {
				if _, err := sc.Subject(context.Background(), mustParse(t, "USDC-"+scanIssuer)); err != nil {
					t.Fatalf("Subject %d: %v", i+1, err)
				}
			}

			if got := atomic.LoadInt64(&directoryRequests); got != 2 {
				t.Errorf("directory fetched %d times across two scans, want 2", got)
			}
			if got := atomic.LoadInt64(&blocklistRequests); got != 2 {
				t.Errorf("blocklist fetched %d times across two scans, want 2", got)
			}
		})
	}
}
