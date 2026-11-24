package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
)

// Every scan answer must be correlatable with the log line that describes it.
// A request identifier is attached to the context here and stamped on every
// log line the request produces, echoed to the caller in a response header —
// so an operator holding one identifier can pull the whole story of a scan
// out of the logs without guessing which lines belong together.
//
// The same wrapper gives handlers the per-request logger every call site
// shares. One pass, one place, so no handler has to remember to do any of it.

// requestIDHeader is the response header the identifier is echoed in. It is
// also accepted on input, so a caller that correlates across services can
// supply its own and see this server use the same value.
//
// An inbound value is only accepted when it is 1 to requestIDMaxLen bytes of
// [A-Za-z0-9._:-]; anything else is ignored and a fresh identifier generated.
// The identifier is echoed in a response header and stamped on every log line
// of the request, so an unbounded or arbitrary value would bloat the logs and
// stop being a usable grep key.
const requestIDHeader = "X-Request-Id"

// requestIDMaxLen is the longest inbound identifier accepted. Correlation
// needs a short opaque token, nothing longer.
const requestIDMaxLen = 128

// validRequestID reports whether an inbound identifier may be reused. Empty,
// over-long, and out-of-charset values are rejected so the server falls back
// to generating one.
func validRequestID(id string) bool {
	if len(id) == 0 || len(id) > requestIDMaxLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

// requestIDLogKey names the structured field the request identifier rides on
// in every log line this package emits.
const requestIDLogKey = "request_id"

type requestIDKey struct{}

type loggerKey struct{}

// RequestID returns the identifier the middleware assigned to the request.
// It returns the empty string outside a request, so call sites that log
// without one degrade to their uncorrelated form instead of printing an
// invented value.
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

// withObservability assigns the request identifier and makes it available
// to the handler and to the logs.
//
// The identifier comes from the caller's header when one is offered and
// acceptable — see validRequestID — and is otherwise freshly generated:
// 16 random bytes, hex-encoded. Both forms are logged the same way: the log
// line records what identified the request, not who chose it.
func (s *Server) withObservability(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if !validRequestID(id) {
			var b [16]byte
			if _, err := rand.Read(b[:]); err != nil {
				// A missing identifier degrades correlation; it must not
				// degrade the request. Unreachable on any working crypto
				// source, and there is no meaningful recovery to attempt.
				http.Error(w, "no request identifier could be generated", http.StatusInternalServerError)
				return
			}
			id = hex.EncodeToString(b[:])
		}

		clientKey := s.ClientKey(r)
		baseLogger := s.Log
		if baseLogger == nil {
			baseLogger = slog.Default()
		}
		logger := baseLogger.With(requestIDLogKey, id, "client_key", clientKey)
		ctx := r.Context()
		ctx = context.WithValue(ctx, requestIDKey{}, id)
		ctx = context.WithValue(ctx, loggerKey{}, logger)

		w.Header().Set(requestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// loggerFrom returns the per-request logger the middleware built, falling
// back to the server's logger when a handler runs outside the middleware —
// so a call site never has to decide which logger to use.
func (s *Server) loggerFrom(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && l != nil {
		return l
	}
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// withCORS applies a permissive CORS policy to every /api/ path: browser
// front-end integrators call the same read-only GET endpoints that server
// clients use. The UI is served same-origin and does not need these headers,
// so they are limited to /api/ prefixes rather than applied globally.
//
// Policy: Allow-Origin: * (GET only, public data). Preflight OPTIONS is
// answered with 204 and no body. The Allow-Headers list covers the
// X-Request-Id input header the middleware accepts; the Expose-Headers list
// covers the response headers consumers read.
func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Accept, "+requestIDHeader)
			w.Header().Set("Access-Control-Expose-Headers", requestIDHeader+", X-Assay-Undetermined, Retry-After")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
