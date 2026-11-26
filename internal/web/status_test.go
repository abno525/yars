package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/logs"
)

// ringOn gives the server a ring and returns a logger that writes to it, as
// yars serve wires the two.
func ringOn(e *env) *slog.Logger {
	e.srv.LogRing = logs.NewRing()
	return slog.New(logs.HandlerRing(io.Discard, logs.Text, slog.LevelInfo, e.srv.LogRing))
}

// Admin › System shows what the server does now: the checks and fixes under
// way, the waiting deliveries and mails, the open event streams by account,
// the repository locks that are held, and the last warn and error lines of
// the ring. It is the admins' page.
func TestSystemPageShowsCurrentState(t *testing.T) {
	e := setup(t)
	lg := ringOn(e)
	if rec := e.do(t, "alice", "GET", "/admin/system", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("a director without the admin flag, or a pentester, opens the page: %d", rec.Code)
	}
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	state := between(b, `id="state"`, "</section>")
	for _, want := range []string{"<h2>Current state</h2>",
		`<span class="sl">Checks running</span><span class="sv">0</span>`, `<span class="sl">Checks queued</span><span class="sv">0</span>`,
		`<span class="sl">Fixes running</span><span class="sv">0</span>`, `<span class="sl">Deliveries waiting</span><span class="sv">0</span>`,
		`<span class="sl">Mails being sent</span><span class="sv">0</span>`,
		`<th>Account</th><th class="c-num">Event streams</th>`, `<th>Repository lock</th><th class="c-num">Held for</th><th class="c-num">Waiting</th>`} {
		if !strings.Contains(state, want) {
			t.Fatalf("the state panel lacks %s:\n%s", want, state)
		}
	}
	// nothing open, held or kept: each table has its empty row
	if n := strings.Count(state, `class="emptyrow"`); n != 2 {
		t.Fatalf("%d empty rows in the state panel:\n%s", n, state)
	}
	logp := between(b, `id="syslog"`, "</section>")
	if !strings.Contains(logp, `<th class="c-time">Time</th><th class="c-state">Level</th><th>Line</th>`) || strings.Count(logp, `class="emptyrow"`) != 1 {
		t.Fatalf("the log panel:\n%s", logp)
	}

	// a stream, a held lock, a waiting delivery and two lines
	for _, u := range []string{"alice", "alice", "bob"} {
		if !e.srv.streamOpen(u) {
			t.Fatal("a stream is not counted")
		}
	}
	unlock := e.srv.Store.LockEngagement("acme")
	defer unlock()
	d := e.srv.Store.DB()
	hook, err := d.AddWebhook(db.Webhook{URL: "https://hooks.example/zqhook7f3kq", Events: []string{"chat.posted"}, SecretEnc: "x", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.EnqueueDelivery(hook, "chat.posted", "{}", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	lg.Info("not kept")
	lg.Warn("webhook delivery failed; it is tried again", "webhook", 3, "password", "zqpassword7f3kq")
	lg.Error("request failed", "err", "open findings/F-001-zqslug7f3kq/finding.md: <b>denied</b>")
	b = e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	state = between(b, `id="state"`, "</section>")
	for _, want := range []string{`<span class="sl">Deliveries waiting</span><span class="sv">1</span>`,
		`<td class="clip" title="alice">alice</td><td class="num">2</td>`, `<td class="clip" title="bob">bob</td><td class="num">1</td>`,
		`<td class="clip" title="acme">acme</td><td class="num">`, `<td class="num">0</td></tr>`} {
		if !strings.Contains(state, want) {
			t.Fatalf("the state panel lacks %s:\n%s", want, state)
		}
	}
	if strings.Contains(state, `class="emptyrow"`) {
		t.Fatalf("an empty row beside rows:\n%s", state)
	}
	logp = between(b, `id="syslog"`, "</section>")
	for _, want := range []string{`<span class="tag warn">WARN</span>`, `<span class="tag bad">ERROR</span>`,
		`msg=&#34;webhook delivery failed; it is tried again&#34; webhook=3`, `findings/F-001/finding.md: &lt;b&gt;denied&lt;/b&gt;`} {
		if !strings.Contains(logp, want) {
			t.Fatalf("the log panel lacks %s:\n%s", want, logp)
		}
	}
	if strings.Contains(b, "zq") || strings.Contains(logp, "not kept") || strings.Contains(logp, "<b>denied") {
		t.Fatalf("the page holds private text, an info line or a line's own HTML:\n%s", logp)
	}
	// the newest line is first
	if strings.Index(logp, "request failed") > strings.Index(logp, "webhook delivery failed") {
		t.Fatalf("the newest line is not first:\n%s", logp)
	}
}

// The status route of yars status answers the same state as JSON, and it
// answers when the database does not: what is in memory is there, what the
// database holds reads as unknown. It serves nothing but that route.
func TestStatusRoute(t *testing.T) {
	e := setup(t)
	lg := ringOn(e)
	e.srv.Version = "v9"
	h := e.srv.StatusHandler()
	get := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec
	}
	for _, p := range []string{"/", "/admin/system", "/login", "/static/app.js"} {
		if rec := get("GET", p); rec.Code != http.StatusNotFound {
			t.Fatalf("the status server answers %s: %d", p, rec.Code)
		}
	}
	if rec := get("POST", "/status"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /status: %d", rec.Code)
	}
	e.srv.streamOpen("alice")
	lg.Warn("login failed", "user", "x\x1b[2J", "password", "zqpassword7f3kq")
	read := func() Status {
		t.Helper()
		rec := get("GET", "/status")
		var st Status
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &st) != nil {
			t.Fatalf("status %d %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "zq") {
			t.Fatalf("the status holds a password: %s", rec.Body.String())
		}
		return st
	}
	st := read()
	if st.Version != "v9" || st.Schema != db.SchemaVersion || st.Started.IsZero() || st.Deliveries != 0 || st.ChecksRunning != 0 ||
		len(st.Streams) != 1 || st.Streams[0] != (StreamCount{User: "alice", Open: 1}) || len(st.Lines) != 1 || st.Lines[0].Level != "WARN" ||
		!strings.Contains(st.Lines[0].Text, `msg="login failed"`) || strings.Contains(st.Lines[0].Text, "\x1b") {
		t.Fatalf("status %+v", st)
	}
	unlock := e.srv.Store.LockEngagement("acme")
	defer unlock()
	e.srv.Store.DB().Close()
	st = read()
	if st.Schema != 0 || st.Deliveries != -1 || len(st.Streams) != 1 || len(st.Lines) != 1 || len(st.Locks) != 1 || st.Locks[0].Eng != "acme" || st.Locks[0].HeldMS <= 0 {
		t.Fatalf("status with the database closed: %+v", st)
	}
}
