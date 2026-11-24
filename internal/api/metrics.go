package api

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Counters, not histograms, and stdlib only. The issue's invariant is no new
// dependency without a maintainer decision, and the numbers that matter here
// are counts: how often scans come back undetermined, which sources failed,
// how many upstream failures there were. Those are monotonically increasing
// integers anyone can render into any monitoring backend later; what this
// file guarantees is that the numbers exist and are cheap to collect.
//
// Everything is guarded by one mutex. Scan traffic is low-frequency by
// design (each scan makes live upstream calls), so a sharded counter would
// be complexity without a measurable win.

// Metrics holds the outcome and per-source counters the issue requires.
//
// The zero value is usable and starts everything at zero, but a Server built
// by NewServer wires its own; tests create one, run traffic, and read it.
type Metrics struct {
	mu sync.Mutex
	// outcomes counts scan results by class: complete, undetermined,
	// not_found, upstream_failure.
	outcomes map[string]uint64
	// sourceFailures counts, per upstream source label, the scans whose
	// report recorded that source as not having answered.
	sourceFailures map[string]uint64
}

// NewMetrics returns a Metrics with all counters at zero.
func NewMetrics() *Metrics {
	return &Metrics{
		outcomes:       map[string]uint64{},
		sourceFailures: map[string]uint64{},
	}
}

// IncOutcome increments the counter for one outcome class.
func (m *Metrics) IncOutcome(class string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.outcomes[class]++
}

// IncSourceFailure increments the failure counter for one upstream source
// label, matching the Source labels the evidence already carries.
func (m *Metrics) IncSourceFailure(source string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sourceFailures[source]++
}

// OutcomeCounts returns a snapshot of the outcome counters.
func (m *Metrics) OutcomeCounts() map[string]uint64 {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]uint64, len(m.outcomes))
	for k, v := range m.outcomes {
		out[k] = v
	}
	return out
}

// SourceFailureCounts returns a snapshot of the per-source failure counters.
func (m *Metrics) SourceFailureCounts() map[string]uint64 {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]uint64, len(m.sourceFailures))
	for k, v := range m.sourceFailures {
		out[k] = v
	}
	return out
}

// metricsBody is the JSON shape served at /metrics. Counters are
// monotonically increasing; a consumer derives rates from consecutive reads.
type metricsBody struct {
	// ScanOutcomes counts scan results per outcome class.
	ScanOutcomes map[string]uint64 `json:"scan_outcomes"`
	// SourceFailures counts, per source label, scans whose report recorded
	// that source as not having answered.
	SourceFailures map[string]uint64 `json:"source_failures"`
}

// handleMetrics serves GET /metrics: the counters this server has collected
// since process start.
//
// By default, it returns JSON over the same HTTP surface as everything else Assay
// serves. When requested via Accept: text/plain; version=0.0.4 or ?format=prometheus,
// it renders the Prometheus text exposition format (version 0.0.4) using only the
// standard library.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	body := metricsBody{
		ScanOutcomes:   map[string]uint64{},
		SourceFailures: map[string]uint64{},
	}
	if s.Metrics != nil {
		body.ScanOutcomes = s.Metrics.OutcomeCounts()
		body.SourceFailures = s.Metrics.SourceFailureCounts()
	}
	if wantsPrometheus(r) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		writePrometheusMetrics(w, body.ScanOutcomes, body.SourceFailures)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

func wantsPrometheus(r *http.Request) bool {
	if r.URL.Query().Get("format") == "prometheus" {
		return true
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	for _, part := range strings.Split(accept, ",") {
		mediaType, params, err := mime.ParseMediaType(strings.TrimSpace(part))
		if err == nil && mediaType == "text/plain" && params["version"] == "0.0.4" {
			return true
		}
	}
	return false
}

func escapePrometheusLabelValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func writePrometheusMetrics(w io.Writer, outcomes, sourceFailures map[string]uint64) {
	_, _ = fmt.Fprintln(w, "# HELP assay_scan_outcomes_total Scan results per outcome class.")
	_, _ = fmt.Fprintln(w, "# TYPE assay_scan_outcomes_total counter")
	classes := make([]string, 0, len(outcomes))
	for c := range outcomes {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		_, _ = fmt.Fprintf(w, "assay_scan_outcomes_total{class=\"%s\"} %d\n", escapePrometheusLabelValue(c), outcomes[c])
	}

	_, _ = fmt.Fprintln(w, "# HELP assay_source_failures_total Scans whose report recorded that source as not having answered.")
	_, _ = fmt.Fprintln(w, "# TYPE assay_source_failures_total counter")
	sources := make([]string, 0, len(sourceFailures))
	for s := range sourceFailures {
		sources = append(sources, s)
	}
	sort.Strings(sources)
	for _, s := range sources {
		_, _ = fmt.Fprintf(w, "assay_source_failures_total{source=\"%s\"} %d\n", escapePrometheusLabelValue(s), sourceFailures[s])
	}
}
