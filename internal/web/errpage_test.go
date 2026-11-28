package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/workflow"
)

// asPage is the header of a browser's page request.
var asPage = map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

// An error answered to a page request is drawn in the layout, with its
// status. A missing engagement, one the account is not on and a missing
// finding in either are the same page: it names nothing from the address.
func TestErrorPageInLayoutLeaksNothing(t *testing.T) {
	e := setup(t)
	e.outsider(t)
	var first string
	for _, p := range []string{"/e/acme", "/e/nosuch", "/e/acme/f/001", "/e/acme/f/999", "/e/nosuch/f/001", "/e/acme/board", "/e/nosuch/board"} {
		rec := e.do(t, "eve", "GET", p, nil, asPage)
		b := rec.Body.String()
		if rec.Code != http.StatusNotFound || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
			t.Fatalf("%s: %d %s", p, rec.Code, rec.Header().Get("Content-Type"))
		}
		for _, want := range []string{`<header class="topbar">`, "<title>Not Found · YARS</title>", "<h1>Not Found</h1>",
			`<tr><th scope="row">Status</th><td class="text mono">404</td></tr>`, `<tr><th scope="row">Reason</th><td class="text">page not found</td></tr>`} {
			if !strings.Contains(b, want) {
				t.Fatalf("%s: the page lacks %s:\n%s", p, want, b)
			}
		}
		for _, never := range []string{"acme", "ACME Web", "nosuch", "SQL injection", "F-001", `data-list=`, `class="crumbs"`, ">Request<"} {
			if strings.Contains(b, never) {
				t.Errorf("%s: the page holds %q", p, never)
			}
		}
		// the engagement of an error page is not kept as the one opened last
		if c := strings.Join(rec.Header().Values("Set-Cookie"), "\n"); strings.Contains(c, lastEngCookie) {
			t.Errorf("%s: the error page keeps an engagement: %s", p, c)
		}
		if first == "" {
			first = b
		} else if b != first {
			t.Errorf("%s: not the same page as /e/acme", p)
		}
	}
	// a member's missing finding is the same page too
	if b := e.do(t, "alice", "GET", "/e/acme/f/999", nil, asPage).Body.String(); !strings.Contains(b, "<h1>Not Found</h1>") || strings.Contains(b, "F-999") {
		t.Errorf("alice, a missing finding:\n%s", b)
	}
}

// Requests that are not a page's keep the plain text: htmx shows it in a
// toast, and a script or a download reads it as it is.
func TestErrorStaysPlainForNonPages(t *testing.T) {
	e := setup(t)
	e.outsider(t)
	for what, hdr := range map[string]map[string]string{
		"no Accept":        nil,
		"htmx":             {"HX-Request": "true", "Accept": "text/html"},
		"a script":         {"Accept": "application/json"},
		"any type":         {"Accept": "*/*"},
		"the event stream": {"Accept": "text/event-stream"},
	} {
		rec := e.do(t, "eve", "GET", "/e/acme", nil, hdr)
		if rec.Code != http.StatusNotFound || rec.Body.String() != "404 page not found\n" || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
			t.Errorf("%s: %d %q %s", what, rec.Code, rec.Body.String(), rec.Header().Get("Content-Type"))
		}
	}
	// an answer that is not an error is untouched
	if rec := e.do(t, "alice", "GET", "/e/acme", nil, asPage); rec.Code != 200 || !strings.Contains(rec.Body.String(), "SQL injection") {
		t.Errorf("the findings list: %d", rec.Code)
	}
	// a page before login keeps its own answers
	if rec := e.do(t, "", "GET", "/static/nosuch.css", nil, asPage); rec.Code != 404 || strings.Contains(rec.Body.String(), "<html") {
		t.Errorf("a static file: %d %q", rec.Code, rec.Body.String())
	}
}

// A refusal says why, in the layout; a server error names its request.
func TestErrorPageReasonAndRequest(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "GET", fpath+"/merge", nil, asPage)
	b := rec.Body.String()
	if rec.Code != http.StatusForbidden || !strings.Contains(b, "<h1>Forbidden</h1>") || !strings.Contains(b, `<td class="text mono">403</td>`) ||
		!strings.Contains(b, `<td class="text">only a director can merge a finding that is not withdrawn</td>`) || strings.Contains(b, ">Request<") {
		t.Fatalf("403: %d\n%s", rec.Code, b)
	}
	// a route that does not exist, and a method a route does not take
	if rec := e.do(t, "alice", "GET", "/nosuch/page", nil, asPage); rec.Code != 404 || !strings.Contains(rec.Body.String(), "<h1>Not Found</h1>") {
		t.Errorf("an unknown route: %d", rec.Code)
	}
	if rec := e.do(t, "alice", "GET", fpath+"/action/clear", nil, asPage); rec.Code != http.StatusMethodNotAllowed || !strings.Contains(rec.Body.String(), "<h1>Method Not Allowed</h1>") {
		t.Errorf("a POST route opened: %d", rec.Code)
	}
	// the inbox cannot be read: 500, with the request's ID as the header has it
	if _, err := e.srv.Store.DB().Exec("ALTER TABLE board_seen RENAME TO board_seen_gone"); err != nil {
		t.Fatal(err)
	}
	rec = e.do(t, "dora", "GET", "/inbox", nil, asPage)
	b, id := rec.Body.String(), rec.Header().Get("X-Request-ID")
	if rec.Code != 500 || id == "" || !strings.Contains(b, "<h1>Internal Server Error</h1>") ||
		!strings.Contains(b, `<tr><th scope="row">Reason</th><td class="text">internal error</td></tr>`) ||
		!strings.Contains(b, `<tr><th scope="row">Request</th><td class="text mono">`+id+`</td></tr>`) {
		t.Fatalf("500: %d id %q\n%s", rec.Code, id, b)
	}
}

// mergeFirst merges F-001 (given a text to bring) into a new F-002 as dora,
// and returns F-002's folder.
func (e *env) mergeFirst(t *testing.T) string {
	t.Helper()
	dst := e.second(t, "alice")
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "All rows of the table.", "", gitrepo.Author{Name: "alice", Email: "alice@yars.local"}); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.Merge("acme", fdir, dst, wDora); err != nil {
		t.Fatal(err)
	}
	return dst
}

// A finding merged into another leads to it: its page redirects, its parts
// and its own address with ?source=1 still answer.
func TestMergedFindingRedirects(t *testing.T) {
	e := setup(t)
	e.mergeFirst(t)
	for _, p := range []string{fshort, fpath, "/e/acme/f/F-001"} {
		rec := e.do(t, "alice", "GET", p, nil, asPage)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/002" {
			t.Fatalf("%s: %d to %q", p, rec.Code, rec.Header().Get("Location"))
		}
	}
	// the source's own page, its parts and its history stay reachable
	b := e.do(t, "alice", "GET", fshort+"?source=1", nil, nil).Body.String()
	if !strings.Contains(b, "merged into F-002") || !strings.Contains(b, "<title>F-001 SQL injection · YARS</title>") {
		t.Fatalf("the source with ?source=1:\n%s", b)
	}
	for _, p := range []string{"/history", "/workflow", "/chat", "/head", "/details"} {
		if rec := e.do(t, "alice", "GET", fshort+p, nil, nil); rec.Code != 200 {
			t.Errorf("the source's %s: %d", p, rec.Code)
		}
	}
	// the target's chat links the source itself
	b = e.do(t, "alice", "GET", "/e/acme/f/002", nil, nil).Body.String()
	if !strings.Contains(b, `merged in: <a class="text" href="/e/acme/f/001?source=1">F-001</a>`) {
		t.Fatalf("the target's merge event has no link to the source:\n%s", between(b, `id="chat-list"`, "</aside>"))
	}
	// an account that is not on the team learns nothing: the stranger's 404
	e.outsider(t)
	if rec := e.do(t, "eve", "GET", fshort, nil, nil); rec.Code != http.StatusNotFound || rec.Header().Get("Location") != "" {
		t.Fatalf("an outsider: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	// restored, the source is a finding again: no redirect
	if err := e.srv.Store.Transition("acme", fdir, workflow.Revise, "", wDora); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "alice", "GET", fshort, nil, nil); rec.Code != 200 {
		t.Fatalf("restored source: %d", rec.Code)
	}
}

// A withdraw reason typed by hand is no merge, and a target that was
// withdrawn later is no place to go.
func TestMergeRedirectNeedsTheMerge(t *testing.T) {
	e := setup(t)
	e.second(t, "alice")
	if err := e.srv.Store.Transition("acme", fdir, workflow.Withdraw, "merged into F-002", wDora); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "alice", "GET", fshort, nil, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "merged into F-002") {
		t.Fatalf("a typed reason redirects: %d", rec.Code)
	}

	e2 := setup(t)
	dst := e2.mergeFirst(t)
	if err := e2.srv.Store.Transition("acme", dst, workflow.Withdraw, "out of scope", wDora); err != nil {
		t.Fatal(err)
	}
	if rec := e2.do(t, "alice", "GET", fshort, nil, nil); rec.Code != 200 {
		t.Fatalf("the target is withdrawn: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
}

// The redirect marks the source's notices read, as opening its page does.
func TestMergeRedirectMarksRead(t *testing.T) {
	e := setup(t)
	e.toVerification(t) // bob gets a notice of F-001
	d := e.srv.Store.DB()
	if n, err := d.UnreadCount("bob"); err != nil || n == 0 {
		t.Fatalf("bob has no notice: %d %v", n, err)
	}
	e.mergeFirst(t)
	before, _ := d.UnreadCount("bob")
	if rec := e.do(t, "bob", "GET", fshort, nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("bob: %d", rec.Code)
	}
	after, _ := d.UnreadCount("bob")
	if after >= before {
		t.Fatalf("the redirect left the source's notices unread: %d, then %d", before, after)
	}
}
