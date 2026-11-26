package web

import (
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/logs"
)

var reqIDRe = regexp.MustCompile(`^[0-9a-f]{8}$`)

// requests are the request lines logged so far.
func (e *env) requests() []logs.Record { return e.log.With("request") }

// Every request is one line of the service log: the ID the server made
// (also the response's X-Request-ID), the method, the route as the mux
// names it, the engagement and the finding by their IDs, who asked, the
// status and the time taken. Nothing of the path's own text (a folder's
// name holds the title's slug) and nothing of the query.
func TestRequestLine(t *testing.T) {
	e := setup(t)
	e.log.Reset()
	rec := e.do(t, "alice", "GET", "/e/acme/f/F-001-sql-injection?x=zqquery7f3kq", nil, map[string]string{"X-Request-ID": "zqclient7f3kq"})
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	id := rec.Header().Get("X-Request-ID")
	if !reqIDRe.MatchString(id) {
		t.Fatalf("X-Request-ID %q: want 8 hex digits the server made", id)
	}
	lines := e.requests()
	if len(lines) != 1 {
		t.Fatalf("want one request line, got:\n%s", e.log.Text())
	}
	l := lines[0]
	for key, want := range map[string]string{"req": id, "method": "GET", "route": "GET /e/{eng}/f/{fid}", "eng": "acme", "finding": "F-001", "user": "alice", "status": "200"} {
		if l.Str(key) != want {
			t.Errorf("%s = %q, want %q (%s)", key, l.Str(key), want, l)
		}
	}
	if _, ok := l.Attrs["ms"].(int64); !ok || l.Level != slog.LevelInfo {
		t.Errorf("ms %v (%T), level %v", l.Attrs["ms"], l.Attrs["ms"], l.Level)
	}
	for _, private := range []string{"sql-injection", "zqquery7f3kq", "zqclient7f3kq", "x="} {
		if strings.Contains(e.log.Text(), private) {
			t.Errorf("the log holds %q:\n%s", private, e.log.Text())
		}
	}
	// a second request has an ID of its own
	if again := e.do(t, "alice", "GET", "/e/acme", nil, nil).Header().Get("X-Request-ID"); again == id || !reqIDRe.MatchString(again) {
		t.Errorf("second ID %q after %q", again, id)
	}
}

// A path no route matches is logged as "-", never as the path; a request
// that is not signed in has no user; the login page's line names no user
// from the form.
func TestRequestLineWithoutRoute(t *testing.T) {
	e := setup(t)
	e.log.Reset()
	if rec := e.do(t, "alice", "GET", "/nope/zqpath7f3kq", nil, nil); rec.Code != 404 {
		t.Fatalf("code %d", rec.Code)
	}
	if l := e.requests(); len(l) != 1 || l[0].Str("route") != "-" || l[0].Str("status") != "404" || l[0].Str("user") != "alice" || strings.Contains(e.log.Text(), "zqpath7f3kq") {
		t.Fatalf("unknown path:\n%s", e.log.Text())
	}
	e.log.Reset()
	e.do(t, "", "GET", "/e/acme/f/F-001-sql-injection", nil, nil)
	if l := e.requests(); len(l) != 1 || l[0].Has("user") || l[0].Str("status") != "303" || strings.Contains(e.log.Text(), "sql-injection") {
		t.Fatalf("not signed in:\n%s", e.log.Text())
	}
	e.log.Reset()
	e.do(t, "", "POST", "/login", map[string][]string{"username": {"zquser7f3kq"}, "password": {"zqpass7f3kq"}}, nil)
	l := e.requests()
	if len(l) != 1 || l[0].Str("route") != "POST /login" || l[0].Has("user") || l[0].Str("status") != "401" {
		t.Fatalf("failed login:\n%s", e.log.Text())
	}
	// the failed-login line is the same request's
	if f := e.log.With("login failed"); len(f) != 1 || f[0].Str("req") != l[0].Str("req") || f[0].Str("req") == "" {
		t.Fatalf("failed login line:\n%s", e.log.Text())
	}
	if strings.Contains(e.log.Text(), "zqpass7f3kq") {
		t.Fatalf("the password is in the log:\n%s", e.log.Text())
	}
}

// A request that fails inside the server names itself three times with one
// ID: the response header, the page ("Request 4f2a9c1b") and the error line
// of the log, next to the request's own line.
func TestRequestIDOnInternalError(t *testing.T) {
	e := setup(t)
	check := func(what, msg string, rec *httptest.ResponseRecorder) {
		t.Helper()
		id := rec.Header().Get("X-Request-ID")
		if rec.Code != 500 || !reqIDRe.MatchString(id) || rec.Body.String() != "internal error\nRequest "+id+"\n" {
			t.Fatalf("%s: code %d id %q body %q", what, rec.Code, id, rec.Body.String())
		}
		errs, reqs := e.log.With(msg), e.requests()
		if len(errs) != 1 || errs[0].Str("req") != id || errs[0].Level != slog.LevelError {
			t.Fatalf("%s: error line:\n%s", what, e.log.Text())
		}
		if len(reqs) != 1 || reqs[0].Str("req") != id || reqs[0].Str("status") != "500" {
			t.Fatalf("%s: request line:\n%s", what, e.log.Text())
		}
	}
	// a handler's error (Server.fail)
	e.log.Reset()
	rec := httptest.NewRecorder()
	e.srv.logRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.srv.fail(w, errors.New("disk gone"))
	})).ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))
	check("fail", "request failed", rec)
	// a template that does not render
	e.srv.pages["finding.html"] = template.Must(template.New("finding.html").Parse(`{{define "layout"}}{{.Nope.Nope}}{{end}}`))
	e.log.Reset()
	check("template", "template error", e.do(t, "alice", "GET", "/e/acme/f/F-001", nil, nil))
	// app.js adds the ID to the toast of a server error, from the header
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	i := strings.Index(js, "'htmx:responseError'")
	if i < 0 || !strings.Contains(js[i:i+1000], "xhr.status >= 500 && xhr.getResponseHeader('X-Request-ID')") || !strings.Contains(js[i:i+1000], "'\\nRequest ' + req") {
		t.Fatal("app.js does not name the request in a server error's toast")
	}
}

// Static files are logged at debug; a request slower than the server's slow
// time is a warning.
func TestRequestLineLevels(t *testing.T) {
	e := setup(t)
	e.log.Reset()
	e.do(t, "", "GET", "/static/app.js", nil, nil)
	if l := e.requests(); len(l) != 1 || l[0].Level != slog.LevelDebug || l[0].Str("route") != "GET /static/" {
		t.Fatalf("static file:\n%s", e.log.Text())
	}
	e.log.Reset()
	e.do(t, "alice", "GET", "/e/acme", nil, nil)
	if l := e.requests(); len(l) != 1 || l[0].Level != slog.LevelInfo {
		t.Fatalf("a page:\n%s", e.log.Text())
	}
	e.srv.slowAfter = time.Nanosecond
	e.log.Reset()
	e.do(t, "alice", "GET", "/e/acme", nil, nil)
	if l := e.requests(); len(l) != 1 || l[0].Level != slog.LevelWarn || l[0].Str("route") != "GET /e/{eng}" {
		t.Fatalf("a slow page:\n%s", e.log.Text())
	}
}

// A request whose handler panics still gets its line (status 500), and the
// panic goes on to net/http.
func TestRequestLineOnPanic(t *testing.T) {
	e := setup(t)
	e.log.Reset()
	var got any
	func() {
		defer func() { got = recover() }()
		e.srv.logRequests(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })).
			ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil))
	}()
	if got != http.ErrAbortHandler {
		t.Fatalf("the panic was swallowed: %v", got)
	}
	if l := e.requests(); len(l) != 1 || l[0].Str("status") != "500" || l[0].Str("route") != "-" {
		t.Fatalf("log:\n%s", e.log.Text())
	}
}

// The event stream is one line, written when it ends: its heartbeats are
// debug lines, and however long it was open it is no slow request.
func TestRequestLineEventStream(t *testing.T) {
	e := setup(t)
	e.srv.heartbeat = 20 * time.Millisecond
	e.srv.slowAfter = time.Millisecond
	ts := e.liveServer(t)
	e.log.Reset()
	s := e.openSSE(t, ts, "eng=acme&f=F-001", nil)
	for range 3 {
		s.waitFor(t, ": ping")
	}
	if l := e.requests(); len(l) != 0 {
		t.Fatalf("a line while the stream is open:\n%s", e.log.Text())
	}
	s.resp.Body.Close()
	deadline := time.Now().Add(5 * time.Second)
	for len(e.requests()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	l := e.requests()
	if len(l) != 1 || l[0].Level != slog.LevelInfo || l[0].Str("route") != "GET /events" || l[0].Str("user") != "alice" || l[0].Str("status") != "200" {
		t.Fatalf("the stream's line:\n%s", e.log.Text())
	}
	beats := e.log.With("event stream heartbeat")
	if len(beats) < 3 || beats[0].Level != slog.LevelDebug || beats[0].Str("req") != l[0].Str("req") {
		t.Fatalf("heartbeats:\n%s", e.log.Text())
	}
}
