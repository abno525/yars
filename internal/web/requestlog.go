package web

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/store"
)

// defaultSlow is how long a request may take before its log line is a
// warning.
const defaultSlow = 2 * time.Second

// The routes whose lines are not at the usual level: static files are
// written at debug, and so is a health probe that was answered 200 (it asks
// every few seconds; one that fails keeps its info line). The event stream
// is open for hours by design, so its one line (written when it ends) is
// never a slow-request warning.
const (
	routeStatic = "GET /static/"
	routeEvents = "GET /events"
	routeHealth = "GET /healthz"
)

// statusWriter remembers the status a handler answered with.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 && code >= 200 { // not an informational 1xx
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Flush sends what is buffered (event streams flush after each event).
func (w *statusWriter) Flush() { http.NewResponseController(w.ResponseWriter).Flush() }

// Unwrap lets http.ResponseController reach the connection (deadlines).
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// logRequests is the outermost handler: it gives each request an ID of the
// server's own making (crypto/rand; a client's X-Request-ID is never read),
// sends it back as X-Request-ID, and writes one log line when the request
// ends: req, method, route, status, ms, then who and what as the inner
// layers named them (logs.Request). The line never holds the path, the
// query or a header. It reads no body. A request that panics gets its line
// too, with status 500 unless it had answered, and the panic goes on.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rq := &logs.Request{ID: logs.NewRequestID()}
		w.Header().Set(logs.HeaderID, rq.ID)
		sw := &statusWriter{ResponseWriter: w}
		start, method, done := time.Now(), r.Method, false
		defer func() {
			status := sw.status
			switch {
			case status != 0:
			case done:
				status = http.StatusOK // a handler that wrote nothing
			default:
				status = http.StatusInternalServerError // it panicked first
			}
			s.requestLine(rq, method, status, time.Since(start))
		}()
		next.ServeHTTP(sw, r.WithContext(logs.WithRequest(r.Context(), rq)))
		done = true
	})
}

// requestLine writes a request's line: at debug for a static file and for a
// health probe answered 200, at warn for a request that took longer than the
// server's slow time (the event stream excepted), else at info.
func (s *Server) requestLine(rq *logs.Request, method string, status int, took time.Duration) {
	lg := s.Logger
	if lg == nil {
		return
	}
	slow := s.slowAfter
	if slow <= 0 {
		slow = defaultSlow
	}
	level := slog.LevelInfo
	switch {
	case rq.Route == routeStatic:
		level = slog.LevelDebug
	case took > slow && rq.Route != routeEvents:
		level = slog.LevelWarn
	case rq.Route == routeHealth && status == http.StatusOK:
		level = slog.LevelDebug
	}
	ctx := context.Background()
	if !lg.Enabled(ctx, level) {
		return
	}
	route := rq.Route
	if route == "" {
		route = "-"
	}
	switch method { // a method is a client's word
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
	default:
		method = "-"
	}
	known := rq.Attrs() // req first
	attrs := make([]slog.Attr, 0, len(known)+4)
	attrs = append(attrs, known[0], slog.String("method", method), slog.String("route", route),
		slog.Int("status", status), slog.Int64("ms", took.Milliseconds()))
	lg.LogAttrs(ctx, level, "request", append(attrs, known[1:]...)...)
}

// routed serves mux and names, on the request's log line, the pattern that
// matched ("-" when none did) and the engagement and finding of its path, by
// their IDs: a finding's folder name is accepted in a path, and it holds the
// title's slug. No other part of a path is logged. An inner mux names the
// route first; an outer one then leaves it.
func routed(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rq := logs.RequestFrom(r.Context())
		if rq == nil {
			mux.ServeHTTP(w, r)
			return
		}
		defer func() { // the mux set the pattern and the path values on r
			route := r.Pattern
			if route == "" {
				route = "-"
			}
			rq.SetRoute(route)
			if eng := r.PathValue("eng"); store.ValidID(eng) && len(eng) <= maxLogEng {
				rq.SetTarget(eng, "")
			}
			if fid := store.LogID(r.PathValue("fid")); fid != "?" {
				rq.SetTarget("", fid)
			}
		}()
		mux.ServeHTTP(w, r)
	})
}

// maxLogEng is the longest engagement ID a request line names.
const maxLogEng = 64

// signedIn names the account on the request's log line, for every request
// that passed the login check. When a gate behind it answers before the
// private mux is reached (an engagement the account is not on), the route is
// still the pattern the path would have matched.
func signedIn(private *http.ServeMux, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rq := logs.RequestFrom(r.Context()); rq != nil {
			rq.SetUser(auth.UserFrom(r.Context()).Username)
			defer func() {
				if rq.Route == "" {
					_, pattern := private.Handler(r)
					if pattern == "" {
						pattern = "-"
					}
					rq.SetRoute(pattern)
				}
			}()
		}
		next.ServeHTTP(w, r)
	})
}

// internalError answers 500 with the request's ID under the words, so a
// report names the log lines of the request ("Request 4f2a9c1b").
func internalError(w http.ResponseWriter) {
	text := "internal error"
	if id := w.Header().Get(logs.HeaderID); id != "" {
		text += "\nRequest " + id
	}
	http.Error(w, text, http.StatusInternalServerError)
}
