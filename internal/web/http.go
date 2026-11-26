package web

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/abno525/yars/internal/logs"
)

// staticHash identifies the embedded static files; it is part of their URLs
// (/static/<hash>/style.css), so they can be cached for good.
var staticHash = func() string {
	h := sha256.New()
	fs.WalkDir(staticFS, "static", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := staticFS.ReadFile(p)
		if err != nil {
			return err
		}
		h.Write([]byte(p + "\x00"))
		h.Write(b)
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))[:12]
}()

// staticPrefix is where templates link static files.
func staticPrefix() string { return "/static/" + staticHash }

func isHash(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, c := range s {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return false
		}
	}
	return true
}

// staticHandler serves the embedded files under /static/. Under the current
// hash they never change (cached for a year); without a hash, or under an
// older one, they are revalidated on each use.
func staticHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/static/")
		cc := "no-cache"
		if seg, after, ok := strings.Cut(rest, "/"); ok && isHash(seg) {
			rest = after
			if seg == staticHash {
				cc = "public, max-age=31536000, immutable"
			}
		}
		if _, err := fs.Stat(sub, rest); err != nil || rest == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", cc)
		r2 := new(http.Request)
		*r2 = *r
		u := *r.URL
		u.Path, u.RawPath = "/"+rest, ""
		r2.URL = &u
		files.ServeHTTP(w, r2)
	})
}

var gzPool = sync.Pool{New: func() any { w, _ := gzip.NewWriterLevel(nil, gzip.DefaultCompression); return w }}

// compressible types: pages, fragments, JSON and the static text files.
func compressible(ct string) bool {
	mt, _, _ := mime.ParseMediaType(ct)
	switch mt {
	case "text/html", "application/json", "text/css", "text/javascript", "application/javascript":
		return true
	}
	return false
}

// gzipHandler compresses HTML, JSON, CSS and JavaScript responses for
// clients that accept gzip. Event streams, downloads (Content-Disposition),
// already-encoded bodies, HEAD and range requests pass through untouched.
func gzipHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead || r.Header.Get("Range") != "" || !acceptsGzip(r.Header.Get("Accept-Encoding")) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Accept-Encoding")
		gw := &gzipWriter{ResponseWriter: w}
		defer gw.close()
		next.ServeHTTP(gw, r)
	})
}

func acceptsGzip(ae string) bool {
	for _, part := range strings.Split(ae, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(name), "gzip") {
			continue
		}
		for _, p := range strings.Split(params, ";") {
			if k, v, _ := strings.Cut(strings.TrimSpace(p), "="); k == "q" {
				q, err := strconv.ParseFloat(v, 64)
				return err == nil && q > 0
			}
		}
		return true
	}
	return false
}

// gzipMin is the smallest body worth compressing: below it gzip's own
// header and trailer make the response bigger.
const gzipMin = 1024

type gzipWriter struct {
	http.ResponseWriter
	gz      *gzip.Writer
	decided bool
	code    int // the status given but not yet sent (waiting for the body size)
}

// decide picks compression for a response of status code whose first write
// is n bytes (-1: unknown, a flush before any write).
func (g *gzipWriter) decide(code, n int) {
	g.decided = true
	h := g.Header()
	if code < 200 || code == http.StatusNoContent || code == http.StatusNotModified ||
		h.Get("Content-Encoding") != "" || h.Get("Content-Disposition") != "" || !compressible(h.Get("Content-Type")) {
		return
	}
	if cl, err := strconv.Atoi(h.Get("Content-Length")); err == nil {
		if cl < gzipMin {
			return
		}
	} else if n >= 0 && n < gzipMin {
		return // a small body in one write (an MCP answer, a fragment)
	}
	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	g.gz = gzPool.Get().(*gzip.Writer)
	g.gz.Reset(g.ResponseWriter)
}

// send decides and writes the held status once the first write's size n is
// known.
func (g *gzipWriter) send(n int) {
	if g.code == 0 {
		g.code = http.StatusOK
	}
	g.decide(g.code, n)
	g.ResponseWriter.WriteHeader(g.code)
}

func (g *gzipWriter) WriteHeader(code int) {
	switch {
	case g.decided:
		g.ResponseWriter.WriteHeader(code)
	case code >= 100 && code < 200:
		g.ResponseWriter.WriteHeader(code) // informational: decide later
	case g.code == 0:
		g.code = code // sent with the first write, when its size is known
	}
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.decided {
		g.send(len(b))
	}
	if g.gz != nil {
		return g.gz.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

// Flush sends what is buffered (event streams flush after each event).
func (g *gzipWriter) Flush() {
	if !g.decided && g.code != 0 {
		g.send(-1)
	}
	if g.gz != nil {
		g.gz.Flush()
	}
	http.NewResponseController(g.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the connection (deadlines).
func (g *gzipWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

func (g *gzipWriter) close() {
	if !g.decided && g.code != 0 {
		g.send(0) // a status without a body
	}
	if g.gz != nil {
		g.gz.Close()
		g.gz.Reset(nil)
		gzPool.Put(g.gz)
		g.gz = nil
	}
}

// longLived lifts the server's read and write deadlines for a request that
// may take longer (event streams, large git transfers).
func longLived(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clearDeadlines(w)
		next.ServeHTTP(w, r)
	})
}

// lintLived extends the write deadline past one whole lint run, for requests
// that run every rule (scripts, AI) before answering: workflow actions and MCP.
func (s *Server) lintLived(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.lintDeadline(w)
		next.ServeHTTP(w, r)
	})
}

// lintDeadline moves the write deadline to one lint run (plus a margin)
// from now; a bulk run calls it again before each row.
func (s *Server) lintDeadline(w http.ResponseWriter) {
	budget := 90 * time.Second // rules.NewEngine's default
	if s.Rules != nil && s.Rules.Budget > 0 {
		budget = s.Rules.Budget
	}
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(budget + 30*time.Second))
}

func clearDeadlines(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Time{}) // errors: not a net/http connection (tests)
	rc.SetWriteDeadline(time.Time{})
}

// HTTPServer is the http.Server for addr with the request timeouts; the
// event stream and git routes lift them per request. What net/http itself
// logs (a failed TLS handshake, a handler's panic) goes to the server's
// logger, a line each at warn; a panic's line has the whole trace in stack.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(logs.StdHandler(s.Logger, "http server"), slog.LevelWarn),
	}
}
