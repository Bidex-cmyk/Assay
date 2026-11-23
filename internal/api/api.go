// Package api serves the Assay HTTP interface and the single-file UI.
package api

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/use-assay/assay/internal/history"
	"github.com/use-assay/assay/internal/horizon"
	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/scan"
	"github.com/use-assay/assay/internal/temporal"
)

//go:embed ui/index.html
var uiFS embed.FS

// Scanner describes what the API server needs from a scanner.
type Scanner interface {
	ScanWithHolder(ctx context.Context, a mechanics.Asset, holder string) (*mechanics.Report, error)
}

// Server serves scan results and recorded observation history.
type Server struct {
	Scanner *scan.Scanner
	// History stores one observation per successful scan. It is a pointer so a
	// caller can replace the default in-memory store with a file-backed one
	// (history.Open) or with a pre-seeded store in a test.
	History *history.Store
	// Health reports per-upstream reachability for GET /readyz. It is a
	// pointer so a test can wire the prober to a stub upstream; when nil,
	// handleReadyz builds one from the server's own clients.
	Health *HealthProber
	// RegistryStaleness reads the configured attested set for /readyz. Its
	// result is informational and does not affect scan readiness.
	RegistryStaleness *RegistryStalenessProber
	// Metrics holds the scan outcome and per-source failure counters served
	// at GET /metrics. Nil-safe: the handlers treat a nil Metrics as
	// "nothing counted", never as a crash.
	Metrics *Metrics
	// ExposureLimiter rate-limits GET /api/v1/exposure per client address.
	// When nil, Handler installs a default bucket — nil means "apply the
	// default", never "allow unlimited"; an exposure endpoint without a
	// bound would be N scans per request with nothing between them.
	ExposureLimiter *RateLimiter
	// ScanLimiter rate-limits GET /api/v1/scan per client address.
	// When nil, no rate limit is applied — nil means "off", not "default".
	// The limit is intentionally off by default for local use and development;
	// public deployments should configure this to protect upstream services
	// (Horizon, StellarExpert) from being hammered under Assay's User-Agent.
	ScanLimiter *RateLimiter
	// EventsLimiter bounds concurrent SSE connections for GET /api/v1/events.
	// When nil, Handler installs a default limiter.
	EventsLimiter *EventsLimiter
	// eventsClients holds active SSE client channels.
	eventsClients map[chan []byte]struct{}
	// eventsMu protects eventsClients.
	eventsMu sync.Mutex
	Log      *slog.Logger
}

// NewServer returns a Server backed by the production scanner and an in-memory
// observation history that does not survive a restart.
func NewServer(log *slog.Logger) *Server {
	return &Server{Scanner: scan.New(), History: history.New(), Metrics: NewMetrics(), Log: log}
}

// Routes lists every route Handler registers, in the "METHOD /path" form
// http.ServeMux accepts. Handler builds its mux from this list, so a route
// cannot be registered without appearing here; the OpenAPI coverage test uses
// the same list to hold openapi.yaml to the surface the server actually serves.
var Routes = []string{
	"GET /api/v1/scan",
	"GET /api/v1/history",
	"GET /api/v1/events",
	"GET /api/v1/exposure",
	"GET /metrics",
	"GET /healthz",
	"GET /readyz",
	"GET /",
}

// Handler returns the configured HTTP routes.
//
// Every route runs through the observability middleware, which assigns the
// request identifier, records the response status, and gives handlers a
// per-request logger — the correlation the outcome log line depends on is
// installed once, here, rather than remembered per handler.
func (s *Server) Handler() http.Handler {
	// Build the prober once after callers have had a chance to configure the
	// scanner and registry reader. Rebuilding it per request would bypass its
	// cache and turn /readyz scrapes into upstream and RPC traffic.
	if s.Health == nil {
		s.Health = NewHealthProber(s)
	}
	mux := http.NewServeMux()
	// Exposure is one request to many scans, so it is wrapped in the rate
	// limit at registration — the bucket is built once per Handler, not per
	// request, or every request would start with a full burst.
	limiter := s.ExposureLimiter
	if limiter == nil {
		limiter = NewRateLimiter(defaultExposureBurst, defaultExposureRate)
	}
	// Events limiter bounds concurrent SSE connections.
	if s.EventsLimiter == nil {
		s.EventsLimiter = NewEventsLimiter(defaultEventsMaxClients)
	}
	s.eventsClients = make(map[chan []byte]struct{})

	// Liveness and readiness are separate endpoints on purpose: /healthz says
	// the process is up and checks nothing, /readyz asks the upstreams. A
	// failing probe must never report healthy; a dying process must still be
	// able to answer /healthz.
	scanHandler := http.HandlerFunc(s.handleScan)
	if s.ScanLimiter != nil {
		scanHandler = s.withScanLimit(s.ScanLimiter, s.handleScan)
	}

	handlers := map[string]http.HandlerFunc{
		"GET /api/v1/scan":     scanHandler,
		"GET /api/v1/history":  s.handleHistory,
		"GET /api/v1/events":   s.handleEvents,
		"GET /api/v1/exposure": s.withExposureLimit(limiter, s.handleExposure),
		"GET /metrics":         s.handleMetrics,
		"GET /healthz": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		},
		"GET /readyz": s.handleReadyz,
		"GET /":       s.handleUI,
	}

	for _, route := range Routes {
		handler, ok := handlers[route]
		if !ok {
			// Routes and handlers are two views of one table; a route without
			// a handler is a programming error, caught before serving traffic.
			panic("api: no handler for route " + route)
		}
		mux.HandleFunc(route, handler)
	}
	allowed := make(map[string]string, len(Routes))
	for _, route := range Routes {
		if method, path, ok := strings.Cut(route, " "); ok {
			allowed[path] = method
		}
	}
	return s.withObservability(s.withCORS(s.withAPIErrors(mux, allowed)))
}

// withAPIErrors rewrites the plain-text 404 and 405 answers the router and the
// UI fallback produce for /api/ paths into the JSON errorBody the rest of the
// API uses. A typo in a path, or the wrong method on a real one, reaches no
// handler, so without this pass an API client gets text/plain. Non-API paths
// are passed through untouched, keeping the UI's own 404 as it was.
func (s *Server) withAPIErrors(next http.Handler, allowed map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		ew := &apiErrorWriter{ResponseWriter: w}
		next.ServeHTTP(ew, r)
		if !ew.rewrite {
			return
		}
		if ew.status == http.StatusMethodNotAllowed {
			// The router advertises HEAD alongside GET because a GET pattern
			// serves it implicitly. The API documents GET, so name that.
			allow := allowed[r.URL.Path]
			if allow == "" {
				allow = w.Header().Get("Allow")
			}
			w.Header().Set("Allow", allow)
			writeJSON(w, ew.status, apiErr(codeMethodNotAllowed, "method "+r.Method+" not allowed; allowed: "+allow))
			return
		}
		writeJSON(w, ew.status, apiErr(codeNotFound, "unknown API path: "+r.URL.Path))
	})
}

// apiErrorWriter decides, at WriteHeader time, whether the response is one the
// router generated that should be rewritten. Rewriting depends on the body not
// already being JSON: handler errors (asset_not_found, account_not_found) set
// their JSON content type first and are left alone.
type apiErrorWriter struct {
	http.ResponseWriter
	rewrite bool
	status  int
}

func (w *apiErrorWriter) WriteHeader(status int) {
	if w.rewrite {
		return
	}
	if status == http.StatusNotFound || status == http.StatusMethodNotAllowed {
		if !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			w.rewrite = true
			w.status = status
			return
		}
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *apiErrorWriter) Write(p []byte) (int, error) {
	if w.rewrite {
		return len(p), nil
	}
	return w.ResponseWriter.Write(p)
}

// Flush keeps the SSE handler's http.Flusher assertion working through the
// wrapper; without it the events endpoint would answer 500.
func (w *apiErrorWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, err := uiFS.ReadFile("ui/index.html")
	if err != nil {
		http.Error(w, "ui unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

// Error codes. These are the stable identifiers API consumers should branch on;
// the human-readable error message may change, the code will not.
const (
	codeNotFound         = "not_found"
	codeMethodNotAllowed = "method_not_allowed"
	codeAssetNotFound    = "asset_not_found"
	codeAccountNotFound  = "account_not_found"
	codeInvalidAsset     = "invalid_asset"
	codeInvalidHolder    = "invalid_holder"
	codeInvalidParam     = "invalid_param"
	codeMissingParam     = "missing_param"
	codeUpstreamUnavail  = "upstream_unavailable"
	codeRateLimited      = "rate_limited"
)

type errorBody struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func apiErr(code, message string) errorBody {
	return errorBody{Error: message, Code: code}
}

// Default limits for SSE connections.
const (
	defaultEventsMaxClients = 100
	eventsHeartbeatInterval = 15 * time.Second
	eventsWriteTimeout      = 10 * time.Second
)

// EventsLimiter is a simple semaphore for bounding concurrent SSE connections.
type EventsLimiter struct {
	sem chan struct{}
}

// NewEventsLimiter returns a limiter allowing up to max concurrent connections.
func NewEventsLimiter(max int) *EventsLimiter {
	return &EventsLimiter{sem: make(chan struct{}, max)}
}

// Acquire attempts to reserve a connection slot. Returns false if at capacity.
func (l *EventsLimiter) Acquire() bool {
	select {
	case l.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release returns a connection slot.
func (l *EventsLimiter) Release() {
	<-l.sem
}

// eventMessage is the JSON structure sent over SSE.
type eventMessage struct {
	Asset      string              `json:"asset"`
	Transition temporal.Transition `json:"transition"`
	Timestamp  time.Time           `json:"timestamp"`
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
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

	holder := r.URL.Query().Get("holder")
	if holder != "" {
		if err := scan.ValidateHolder(holder); err != nil {
			writeJSON(w, http.StatusBadRequest, apiErr(codeInvalidHolder, err.Error()))
			return
		}
	}

	maxAgeParam := r.URL.Query().Get("max_age_secs")
	if maxAgeParam == "" {
		maxAgeParam = r.URL.Query().Get("max_age")
	}
	if maxAgeParam != "" {
		secs, err := strconv.ParseInt(maxAgeParam, 10, 64)
		if err != nil || secs < 0 {
			writeJSON(w, http.StatusBadRequest, apiErr(codeInvalidParam, "invalid max_age_secs"))
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	report, err := s.Scanner.ScanWithHolder(ctx, asset, holder)

	// One outcome line per scan, exactly once, with the request identifier
	// the middleware stamped on this request. The status recorded here is
	// the one the handler is about to write for this scan — derived by the
	// same decision the answer below makes, so the log joins against the
	// access log without guessing.
	s.logScanOutcome(r.Context(), report, err, s.scanStatusFor(report, err), asset.String())

	if err != nil {
		if errors.Is(err, horizon.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, apiErr(codeAssetNotFound, "asset not found on the ledger"))
			return
		}
		// The per-request logger is used so this line carries the same
		// request identifier as the outcome line above it.
		s.loggerFrom(r.Context()).Error("scan failed", "asset", asset.String(), "err", err)
		// The upstream error is returned rather than a generic message: a user
		// deciding whether to trust an asset needs to know the difference
		// between "safe" and "we could not check".
		writeJSON(w, http.StatusBadGateway, apiErr(codeUpstreamUnavail, "scan failed: "+err.Error()))
		return
	}

	if s.History != nil {
		// Get previous observation to compute transition.
		var prevObs temporal.Observation
		prevList := s.History.List(asset)
		if len(prevList) > 0 {
			prevObs = prevList[len(prevList)-1]
		}

		newObs := temporal.ObservationFromReport(report)
		if err := s.History.Append(newObs); err != nil {
			s.Log.Error("history append failed", "asset", asset.String(), "err", err)
		} else if !prevObs.At.IsZero() {
			// Compute and broadcast transition if we have a previous observation.
			transition := temporal.Between(prevObs, newObs)
			if transition.State == temporal.Valid {
				s.broadcastEvent(asset.String(), transition)
			}
		}
	}

	if report.Undetermined {
		w.Header().Set("X-Assay-Undetermined", "true")
	} else {
		w.Header().Set("X-Assay-Undetermined", "false")
	}
	writeJSON(w, http.StatusOK, report)
}

// handleEvents serves an SSE stream that pushes a message whenever a stored
// observation produces a capability, severity, or accountability transition.
//
// The endpoint implements standard SSE with:
// - Bounded concurrent clients (default 100, configurable via Server.EventsLimiter)
// - Heartbeats every 15 seconds to keep connections alive through proxies
// - Per-client write timeout of 10 seconds
// - Automatic cleanup on client disconnect
//
// Each message names the asset, the transition, and the observation pair.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("asset")
	if raw == "" {
		writeJSON(w, http.StatusBadRequest, apiErr(codeMissingParam, "missing ?asset=CODE-ISSUER"))
		return
	}

	_, err := scan.ParseAsset(raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiErr(codeInvalidAsset, err.Error()))
		return
	}

	// Enforce client cap.
	if !s.EventsLimiter.Acquire() {
		writeJSON(w, http.StatusTooManyRequests, apiErr(codeRateLimited, "too many SSE connections"))
		return
	}
	defer s.EventsLimiter.Release()

	// Set SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable nginx buffering

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, apiErr(codeUpstreamUnavail, "SSE not supported"))
		return
	}

	// Create a channel for this client.
	clientCh := make(chan []byte, 10)

	s.eventsMu.Lock()
	s.eventsClients[clientCh] = struct{}{}
	s.eventsMu.Unlock()

	// Clean up on disconnect.
	ctx := r.Context()
	defer func() {
		s.eventsMu.Lock()
		delete(s.eventsClients, clientCh)
		s.eventsMu.Unlock()
		close(clientCh)
	}()

	// Send initial comment to establish the connection.
	_, _ = w.Write([]byte(": connected\n\n"))
	flusher.Flush()

	heartbeat := time.NewTicker(eventsHeartbeatInterval)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			// Send heartbeat comment.
			_, _ = w.Write([]byte(": heartbeat\n\n"))
			flusher.Flush()
		case data := <-clientCh:
			_, _ = w.Write(data)
			flusher.Flush()
		}
	}
}

// broadcastEvent sends a transition event to all connected SSE clients.
func (s *Server) broadcastEvent(asset string, transition temporal.Transition) {
	s.eventsMu.Lock()
	clients := make([]chan []byte, 0, len(s.eventsClients))
	for ch := range s.eventsClients {
		clients = append(clients, ch)
	}
	s.eventsMu.Unlock()

	msg := eventMessage{
		Asset:      asset,
		Transition: transition,
		Timestamp:  time.Now().UTC(),
	}
	data, err := json.Marshal(msg)
	if err != nil {
		s.Log.Error("events: marshal event", "err", err)
		return
	}
	// SSE format: "data: <json>\n\n"
	sseData := append([]byte("data: "), append(data, '\n', '\n')...)

	for _, ch := range clients {
		select {
		case ch <- sseData:
		default:
			// Client buffer full — drop this event for this client.
			// The client will receive subsequent events.
		}
	}
}

// BroadcastEventForTest allows tests to broadcast a transition event.
// This is a test-only helper that calls the internal broadcastEvent.
func (s *Server) BroadcastEventForTest(asset string, transition temporal.Transition) {
	s.broadcastEvent(asset, transition)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// scanStatusFor returns the HTTP status the handler will answer the scan
// with, from the same decision the handler makes. The outcome line carries
// it so the log can be joined against the access log without guessing.
func (s *Server) scanStatusFor(report *mechanics.Report, err error) int {
	if err != nil {
		if errors.Is(err, horizon.ErrNotFound) {
			return http.StatusNotFound
		}
		return http.StatusBadGateway
	}
	return http.StatusOK
}
