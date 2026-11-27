package web

import (
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// healthBody is what /healthz answers to anyone while the server works.
const healthBody = "ok\n"

// GET /healthz answers a probe without a login: 200 and one fixed word. It
// says nothing else (no version, no cookie), the same to an account as to a
// stranger, and its line in the log is at debug, since a probe asks every
// few seconds.
func TestHealthz(t *testing.T) {
	e := setup(t)
	e.srv.Version = "zqversion7f3kq"
	e.log.Reset()
	rec := e.do(t, "", "GET", "/healthz", nil, nil)
	if rec.Code != 200 || rec.Body.String() != healthBody {
		t.Fatalf("code %d, body %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("headers %v", rec.Header())
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Errorf("cookies %v", rec.Result().Cookies())
	}
	for key, vals := range rec.Header() {
		if strings.Contains(key+strings.Join(vals, " "), "zqversion7f3kq") {
			t.Errorf("the version is in header %s", key)
		}
	}
	l := e.requests()
	if len(l) != 1 || l[0].Level != slog.LevelDebug || l[0].Str("route") != "GET /healthz" || l[0].Str("status") != "200" || l[0].Has("user") {
		t.Fatalf("request line:\n%s", e.log.Text())
	}
	// a signed-in request reads the same, and is no line of that account
	e.log.Reset()
	rec = e.do(t, "alice", "GET", "/healthz", nil, nil)
	if rec.Code != 200 || rec.Body.String() != healthBody || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("signed in: code %d, body %q", rec.Code, rec.Body.String())
	}
	if l := e.requests(); len(l) != 1 || l[0].Has("user") {
		t.Fatalf("signed in:\n%s", e.log.Text())
	}
	// HEAD is answered too; a POST is not a probe
	if rec := e.do(t, "", "HEAD", "/healthz", nil, nil); rec.Code != 200 {
		t.Errorf("HEAD: %d", rec.Code)
	}
	if rec := e.do(t, "", "POST", "/healthz", nil, nil); rec.Code != 405 {
		t.Errorf("POST: %d", rec.Code)
	}
}

// A server without an account answers the probe as any other: it is not
// sent to /setup, so the answer does not tell a stranger the server is new.
func TestHealthzBeforeSetup(t *testing.T) {
	e := fresh(t)
	rec := e.do(t, "", "GET", "/healthz", nil, nil)
	if rec.Code != 200 || rec.Body.String() != healthBody || rec.Header().Get("Location") != "" {
		t.Fatalf("code %d, body %q, to %q", rec.Code, rec.Body.String(), rec.Header().Get("Location"))
	}
}

// A database that does not answer is 503 and one fixed word: never the
// error, which names the file. The log gets one warn line when the answer
// turns bad, not one per probe; the failed probes' request lines are at
// info.
func TestHealthzDatabaseDown(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "", "GET", "/healthz", nil, nil); rec.Code != 200 {
		t.Fatalf("before: %d", rec.Code)
	}
	e.srv.Store.DB().Close()
	e.log.Reset()
	for i := range 3 {
		rec := e.do(t, "", "GET", "/healthz", nil, nil)
		body := rec.Body.String()
		if rec.Code != 503 || body != "unavailable\n" {
			t.Fatalf("probe %d: code %d, body %q", i, rec.Code, body)
		}
		for _, private := range []string{"yars.db", e.dir, "sql", "database", "closed"} {
			if strings.Contains(body, private) {
				t.Fatalf("the body holds %q: %q", private, body)
			}
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("headers %v", rec.Header())
		}
	}
	if w := e.log.With("health check failed"); len(w) != 1 || w[0].Level != slog.LevelWarn || !w[0].Has("err") {
		t.Fatalf("want one warn line for the change:\n%s", e.log.Text())
	}
	if l := e.requests(); len(l) != 3 || l[0].Level != slog.LevelInfo || l[0].Str("status") != "503" {
		t.Fatalf("request lines:\n%s", e.log.Text())
	}
}

// A database that hangs: the probe is answered 503 after the server's wait,
// the probes that follow are answered at once and start no second read, and
// once the read returns the answer is good again, with one line for each
// change.
func TestHealthzDatabaseHangs(t *testing.T) {
	e := setup(t)
	release := make(chan struct{})
	var reads atomic.Int64
	e.srv.healthProbe = func() error {
		if reads.Add(1) == 1 {
			<-release // the first read hangs
		}
		return nil
	}
	e.srv.healthWait = time.Nanosecond
	e.log.Reset()
	for i := range 3 {
		if rec := e.do(t, "", "GET", "/healthz", nil, nil); rec.Code != 503 || rec.Body.String() != "unavailable\n" {
			t.Fatalf("probe %d: code %d, body %q", i, rec.Code, rec.Body.String())
		}
	}
	// the read starts on its own goroutine: give it time to begin
	for deadline := time.Now().Add(30 * time.Second); reads.Load() == 0 && time.Now().Before(deadline); {
		time.Sleep(time.Millisecond)
	}
	if n := reads.Load(); n != 1 {
		t.Fatalf("%d reads of the database for three probes of a hanging one, want 1", n)
	}
	if w := e.log.With("health check failed"); len(w) != 1 {
		t.Fatalf("want one warn line:\n%s", e.log.Text())
	}
	// the read returns: the next probe waits for it, or starts a new one
	e.srv.healthWait = time.Hour
	close(release)
	if rec := e.do(t, "", "GET", "/healthz", nil, nil); rec.Code != 200 || rec.Body.String() != healthBody {
		t.Fatalf("after: code %d, body %q", rec.Code, rec.Body.String())
	}
	if l := e.log.With("health check passes again"); len(l) != 1 || l[0].Level != slog.LevelInfo {
		t.Fatalf("want one line for the change back:\n%s", e.log.Text())
	}
}
