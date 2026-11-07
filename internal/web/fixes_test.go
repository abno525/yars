package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/workflow"
)

// The findings board refreshes itself on the engagement's events (a push,
// an edit, a state change elsewhere) with its filters kept, and brings the
// progress panel along; it holds off while rows are picked or more loaded.
func TestFindingsBoardLive(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme?sort=title", nil, nil).Body.String()
	head := between(b, `<div id="findings"`, ">")
	for _, want := range []string{`data-sse-url="/events?eng=acme"`, `hx-get="/e/acme?sort=title"`, "sse:content", "sse:workflow", "sse:resync", "yarsListIdle()", "data-sse"} {
		if !strings.Contains(head, want) {
			t.Errorf("findings head lacks %q: %s", want, head)
		}
	}
	rec := e.do(t, "alice", "GET", "/e/acme?sort=title", nil, map[string]string{"HX-Request": "true", "HX-Trigger": "findings"})
	if body := rec.Body.String(); !strings.Contains(body, `id="findings"`) || !strings.Contains(body, `id="engbars" hx-swap-oob="true"`) {
		t.Fatalf("live refresh:\n%s", body)
	}
	if body := e.do(t, "alice", "GET", "/e/acme?sort=title", nil, map[string]string{"HX-Request": "true"}).Body.String(); strings.Contains(body, "hx-swap-oob") {
		t.Fatal("a filter click sends the bars out of band")
	}
	if js := e.do(t, "alice", "GET", staticPrefix()+"/app.js", nil, nil).Body.String(); !strings.Contains(js, "yarsListIdle") {
		t.Fatal("app.js lacks yarsListIdle")
	}
}

// The editor's attachment strip has a bounded height and scrolls: a finding
// with thousands of attachments made the editor 327,680 px tall.
func TestAttachStripBounded(t *testing.T) {
	e := setup(t)
	css := e.do(t, "alice", "GET", staticPrefix()+"/style.css", nil, nil).Body.String()
	rule := between(css, ".attstrip {", "}")
	if !strings.Contains(rule, "max-height: 440px") || !strings.Contains(rule, "overflow-y: auto") {
		t.Fatalf(".attstrip rule: %s", rule)
	}
}

// The page keeps room for a scrollbar, so the top bar and right-aligned
// buttons stay put between short and long pages.
func TestRootScrollbarGutter(t *testing.T) {
	e := setup(t)
	css := e.do(t, "alice", "GET", staticPrefix()+"/style.css", nil, nil).Body.String()
	if rule := between(css, "\nhtml {", "}"); !strings.Contains(rule, "scrollbar-gutter: stable") {
		t.Fatalf("html rule: %q", rule)
	}
}

// History names the front matter part a version changed: a title edit is
// "edited the title", not "edited details".
func TestHistoryNamesFrontMatterPart(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	alice := e.authorOf(config.User{Username: "alice", Role: "pentester"})
	if err := st.UpdateTitle("acme", "F-001-sql-injection", "Blind SQL injection", alice); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSeverity("acme", "F-001-sql-injection", "high", "", alice); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/acme/f/001/history", nil, nil).Body.String()
	for _, want := range []string{"edited the title", "edited severity"} {
		if !strings.Contains(b, want) {
			t.Errorf("history lacks %q", want)
		}
	}
	if strings.Contains(b, "edited details") {
		t.Error("a title or severity edit labelled \"edited details\"")
	}
}

// Notifications show the finding's title as it is now.
func TestNotificationsCurrentTitle(t *testing.T) {
	e := setup(t)
	returnToAlice(t, e)
	if err := e.srv.Store.UpdateTitle("acme", "F-001-sql-injection", "Blind SQL injection in login", e.authorOf(config.User{Username: "dora", Role: "director"})); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String()
	if !strings.Contains(b, "Blind SQL injection in login") {
		t.Fatalf("notifications keep the old title:\n%s", between(b, "<tbody", "</tbody>"))
	}
	// a withdrawn finding is left off the board but keeps its current title here
	if err := e.srv.Store.Transition("acme", "F-001-sql-injection", workflow.Withdraw, "dup", config.User{Username: "alice", Role: "pentester"}); err != nil {
		t.Fatal(err)
	}
	if b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String(); !strings.Contains(b, "Blind SQL injection in login") {
		t.Fatalf("withdrawn finding shows the old title:\n%s", between(b, "<tbody", "</tbody>"))
	}
}

// A title made only of bidi controls is empty once cleaned: the form says
// so (400 with the form), not a bare error from the store.
func TestNewFindingBidiOnlyTitle(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"\u202e\u2066"}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Title is required.") {
		t.Fatalf("%d:\n%s", rec.Code, rec.Body)
	}
}

// A finding ID (F-001, as MCP, chat and reports name it) opens the finding
// like its number or folder does.
func TestFindingByID(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/e/acme/f/F-001", "/e/acme/f/F-1", "/e/acme/f/F-001/history"} {
		rec := e.do(t, "alice", "GET", p, nil, nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "SQL injection") {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	if rec := e.do(t, "alice", "GET", "/e/acme/f/F-099", nil, nil); rec.Code != 404 {
		t.Errorf("unknown ID: %d", rec.Code)
	}
}
