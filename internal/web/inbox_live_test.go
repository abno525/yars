package web

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/events"
)

// liveNames are the events the Inbox and the badge listen to.
var liveNames = []string{"sse:notice", "sse:workflow", "sse:content", "sse:chat", "sse:check", "sse:resync", "sse:poll"}

var inboxStamp = regexp.MustCompile(`hx-get="/inbox\?live=1&amp;h=([0-9a-f]+)"`)

// The Inbox's queues sit in one element that opens the stream of every
// engagement and fetches itself again on its events; a director's bulk form
// is inside it, so a run's own swap leaves it there.
func TestInboxRefreshesLive(t *testing.T) {
	e := setup(t)
	for _, u := range []string{"bob", "dora"} {
		b := e.do(t, u, "GET", "/inbox", nil, nil).Body.String()
		tag := openTag(t, b, "inbox-live")
		for _, want := range append([]string{`data-sse-url="/events"`, ` data-sse>`, `hx-swap="outerHTML"`, `data-rows="`}, liveNames...) {
			if !strings.Contains(tag, want) {
				t.Errorf("%s: #inbox-live lacks %s: %s", u, want, tag)
			}
		}
		if !inboxStamp.MatchString(tag) {
			t.Errorf("%s: #inbox-live has no stamp: %s", u, tag)
		}
		if strings.Count(b, "data-sse-url=") != 1 {
			t.Errorf("%s: %d streams named on the page", u, strings.Count(b, "data-sse-url="))
		}
		in := b[strings.Index(b, tag):]
		in = in[:strings.Index(in, `<form id="notes"`)]
		if has := strings.Contains(in, `<form class="fbulkform" hx-post="/inbox/bulk" hx-target="this"`); has != (u == "dora") {
			t.Errorf("%s: the bulk form inside #inbox-live: %v", u, has)
		}
		if !strings.Contains(in, `class="inbox"`) {
			t.Errorf("%s: the queues are not inside #inbox-live", u)
		}
		// on the Inbox the queues' request brings the badge: its link fetches nothing
		if nav := inboxNav(t, b); strings.Contains(nav, "hx-get") || strings.Contains(nav, "data-sse") {
			t.Errorf("%s: the Inbox page's badge fetches itself too: %s", u, nav)
		}
	}
}

// inboxNav is the top bar's Inbox link in b.
func inboxNav(t *testing.T, b string) string {
	t.Helper()
	m := regexp.MustCompile(`<a [^>]*id="inbox-nav"[^>]*>`).FindString(b)
	if m == "" {
		t.Fatalf("no Inbox link:\n%s", between(b, `<nav class="nav">`, "</nav>"))
	}
	return m
}

// The top bar's badge follows the page's stream: the Inbox link fetches its
// own text on the stream's events. It names no stream, so a page keeps the
// one it has (a finding page its own).
func TestBadgeRefreshesLive(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/", "/e/acme", fshort, "/e/acme/board", "/settings", "/admin/users"} {
		rec := e.do(t, "dora", "GET", p, nil, nil)
		if rec.Code != 200 {
			t.Fatalf("%s: %d", p, rec.Code)
		}
		b := rec.Body.String()
		nav := inboxNav(t, b)
		for _, want := range append([]string{`href="/inbox"`, `hx-get="/inbox/badge"`, `hx-swap="innerHTML"`, ` data-sse `}, liveNames...) {
			if !strings.Contains(nav, want) {
				t.Errorf("%s: the Inbox link lacks %s: %s", p, want, nav)
			}
		}
		if strings.Contains(nav, "data-sse-url") {
			t.Errorf("%s: the badge names a stream: %s", p, nav)
		}
	}
	b := e.do(t, "dora", "GET", fshort, nil, nil).Body.String()
	if n := strings.Count(b, "data-sse-url="); n != 1 || !strings.Contains(b, `data-sse-url="/events?eng=acme&amp;f=F-001"`) {
		t.Errorf("the finding page names %d streams", n)
	}
	// the badge alone, per account
	e.outsider(t)
	e.toVerification(t)
	hx := map[string]string{"HX-Request": "true", "HX-Trigger": "inbox-nav"}
	rec := e.do(t, "bob", "GET", "/inbox/badge", nil, hx)
	if rec.Code != 200 || !regexp.MustCompile(`^Inbox <span class="badge">[1-9]\d*</span>$`).MatchString(strings.TrimSpace(rec.Body.String())) {
		t.Fatalf("bob's badge: %d %q", rec.Code, rec.Body.String())
	}
	if rec := e.do(t, "eve", "GET", "/inbox/badge", nil, hx); rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != `Inbox <span class="badge0">0</span>` {
		t.Fatalf("an outsider's badge: %d %q", rec.Code, rec.Body.String())
	}
	if rec := e.do(t, "", "GET", "/inbox/badge", nil, hx); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: %d", rec.Code)
	}
}

// The Inbox's own request answers the queues and the badge out of band, and
// nothing while what it would draw is what the page shows.
func TestInboxLiveAnswer(t *testing.T) {
	e := setup(t)
	hx := map[string]string{"HX-Request": "true", "HX-Trigger": "inbox-live"}
	page := e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String()
	m := inboxStamp.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("the Inbox has no stamp")
	}
	if rec := e.do(t, "bob", "GET", "/inbox?live=1&h="+m[1], nil, hx); rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("an unchanged Inbox: %d\n%s", rec.Code, rec.Body.String())
	}
	e.toVerification(t) // a finding for bob to review
	rec := e.do(t, "bob", "GET", "/inbox?live=1&h="+m[1], nil, hx)
	b := rec.Body.String()
	if rec.Code != 200 || strings.Contains(b, "<html") {
		t.Fatalf("a changed Inbox: %d\n%s", rec.Code, b)
	}
	if q := queue(b, "review"); !strings.Contains(q, "SQL injection") {
		t.Fatalf("the new row is not in Awaiting my review:\n%s", b)
	}
	tag := openTag(t, b, "inbox-live")
	now := inboxStamp.FindStringSubmatch(tag)
	if now == nil || now[1] == m[1] {
		t.Fatalf("the answer's stamp: %s", tag)
	}
	if !regexp.MustCompile(`<a id="inbox-nav" hx-swap-oob="innerHTML">Inbox <span class="badge">[1-9]\d*</span></a>`).MatchString(b) {
		t.Fatalf("the badge is not sent out of band:\n%s", b)
	}
	if rec := e.do(t, "bob", "GET", "/inbox?live=1&h="+now[1], nil, hx); rec.Code != http.StatusNoContent {
		t.Fatalf("the answer's own stamp: %d", rec.Code)
	}
	// a page request with the parameter is the page
	if b := e.do(t, "bob", "GET", "/inbox?live=1&h="+now[1], nil, nil).Body.String(); !strings.Contains(b, "<html") {
		t.Fatal("/inbox?live=1 opened as a page is not the page")
	}
}

// nextEvent reads sub until an event of kind comes, and fails the test when
// none does (the deadline is generous: nothing here waits on purpose).
func nextEvent(t *testing.T, sub *events.Sub, kind string) events.Event {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case ev := <-sub.C():
			if ev.Kind == kind {
				return ev
			}
		case <-deadline:
			t.Fatalf("no %s event", kind)
		}
	}
}

// A notice is written after the page was told of the change that caused it.
// The page is told once more, after the notice is there, so the refetch it
// answers with finds the row.
func TestNoticeEventComesAfterTheNotice(t *testing.T) {
	e := setup(t)
	d := e.srv.Store.DB()
	if n, _ := d.UnreadCount("bob"); n != 0 {
		t.Fatalf("bob starts with %d notices", n)
	}
	sub := e.srv.Events.Subscribe("", "", 64)
	defer e.srv.Events.Unsubscribe(sub)
	e.toVerification(t)
	ev := nextEvent(t, sub, events.Notice)
	if n, _ := d.UnreadCount("bob"); n == 0 {
		t.Fatal("the notice event came before the notice")
	}
	if ev.Eng != "acme" || ev.Fid != "" {
		t.Fatalf("the notice event: %+v", ev)
	}
	// a team board change reaches the stream of every engagement as a notice
	// (its own event goes to the board page only)
	sub2 := e.srv.Events.Subscribe("", "", 64)
	defer e.srv.Events.Unsubscribe(sub2)
	if rec := e.do(t, "alice", "POST", "/e/acme/board", map[string][]string{"title": {"JWT alg none"}, "state": {"open"}, "text": {"Token with alg none."}}, nil); rec.Code != 200 {
		t.Fatalf("new lead: %d", rec.Code)
	}
	if ev := nextEvent(t, sub2, events.Notice); ev.Eng != "acme" {
		t.Fatalf("the board's notice event: %+v", ev)
	}
}

// The script: the browser hears notice events, and an Inbox in use is not
// refreshed under the user's hands.
func TestInboxLiveScript(t *testing.T) {
	e := setup(t)
	sse := e.do(t, "alice", "GET", "/static/sse.js", nil, nil).Body.String()
	if !strings.Contains(sse, "var NAMES = ['chat', 'workflow', 'content', 'presence', 'check', 'board', 'notice'];") {
		t.Error("sse.js does not hear notice events")
	}
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	idle := jsFunc(t, js, "function yarsInboxIdle()", "\n}\n")
	for _, want := range []string{
		"getElementById('inbox-live')",
		"input[name=id]:checked", "input[name=reviewer]:checked", // ticked rows and names
		"[data-bulk-menu][aria-expanded=true]", // an open menu
		".bdlg:not([hidden])",                  // the reason panel, with its text
		".bsum", "tr.skip",                     // a run's summary and rows
		".htmx-request", // a run that is out
		"data-rows",     // rows appended by Load more
	} {
		if !strings.Contains(idle, want) {
			t.Errorf("yarsInboxIdle lacks %q:\n%s", want, idle)
		}
	}
	if !strings.Contains(js, "if (el && el.id === 'inbox-live' && ev && String(ev.type).indexOf('sse:') === 0 && !yarsInboxIdle()) evt.preventDefault();") {
		t.Error("a live request of the Inbox is not held while it is in use")
	}
}
