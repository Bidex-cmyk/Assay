package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetricsJSONDefault(t *testing.T) {
	srv := NewServer(nil)
	srv.Metrics.IncOutcome("complete")
	srv.Metrics.IncSourceFailure("horizon")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("expected application/json; charset=utf-8, got %q", contentType)
	}

	var body metricsBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal JSON body: %v", err)
	}
	if body.ScanOutcomes["complete"] != 1 {
		t.Errorf("expected complete=1, got %d", body.ScanOutcomes["complete"])
	}
	if body.SourceFailures["horizon"] != 1 {
		t.Errorf("expected horizon=1, got %d", body.SourceFailures["horizon"])
	}
}

func TestMetricsPrometheusFormatParam(t *testing.T) {
	srv := NewServer(nil)
	srv.Metrics.IncOutcome("complete")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics?format=prometheus", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	contentType := rec.Header().Get("Content-Type")
	if contentType != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("expected text/plain; version=0.0.4; charset=utf-8, got %q", contentType)
	}
}

func TestMetricsPrometheusAcceptHeader(t *testing.T) {
	srv := NewServer(nil)
	srv.Metrics.IncOutcome("complete")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Accept", "text/plain; version=0.0.4")
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	contentType := rec.Header().Get("Content-Type")
	if contentType != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("expected text/plain; version=0.0.4; charset=utf-8, got %q", contentType)
	}
}

func TestMetricsNonPrometheusAcceptDefaultsToJSON(t *testing.T) {
	srv := NewServer(nil)

	for _, accept := range []string{
		"text/plain",
		"text/plain; version=1.0.0",
		"application/json",
		"*/*",
		"",
	} {
		t.Run("accept="+accept, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			if accept != "" {
				req.Header.Set("Accept", accept)
			}
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d", rec.Code)
			}
			contentType := rec.Header().Get("Content-Type")
			if contentType != "application/json; charset=utf-8" {
				t.Errorf("expected application/json; charset=utf-8, got %q", contentType)
			}
		})
	}
}

func TestMetricsPrometheusGolden(t *testing.T) {
	srv := NewServer(nil)

	// Populate counts out of order to ensure alphabetical sorting
	srv.Metrics.IncOutcome("undetermined")
	srv.Metrics.IncOutcome("complete")
	srv.Metrics.IncOutcome("complete")
	srv.Metrics.IncOutcome("not_found")
	srv.Metrics.IncOutcome("upstream_failure")

	// Include label value needing escaping: backslash, quotes, and newline
	srv.Metrics.IncSourceFailure("horizon")
	srv.Metrics.IncSourceFailure("custom\\source\"with\nescapes")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics?format=prometheus", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	const expectedGolden = `# HELP assay_scan_outcomes_total Scan results per outcome class.
# TYPE assay_scan_outcomes_total counter
assay_scan_outcomes_total{class="complete"} 2
assay_scan_outcomes_total{class="not_found"} 1
assay_scan_outcomes_total{class="undetermined"} 1
assay_scan_outcomes_total{class="upstream_failure"} 1
# HELP assay_source_failures_total Scans whose report recorded that source as not having answered.
# TYPE assay_source_failures_total counter
assay_source_failures_total{source="custom\\source\"with\nescapes"} 1
assay_source_failures_total{source="horizon"} 1
`

	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if string(body) != expectedGolden {
		t.Errorf("unexpected Prometheus exposition output.\nGot:\n%s\nWant:\n%s", string(body), expectedGolden)
	}
}

func TestMetricsPrometheusEmpty(t *testing.T) {
	srv := NewServer(nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics?format=prometheus", nil)
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	const expectedEmpty = `# HELP assay_scan_outcomes_total Scan results per outcome class.
# TYPE assay_scan_outcomes_total counter
# HELP assay_source_failures_total Scans whose report recorded that source as not having answered.
# TYPE assay_source_failures_total counter
`

	body := rec.Body.String()
	if body != expectedEmpty {
		t.Errorf("unexpected empty Prometheus output.\nGot:\n%s\nWant:\n%s", body, expectedEmpty)
	}
}
