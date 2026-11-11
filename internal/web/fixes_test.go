package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/store"
	"yars/internal/workflow"
)

// The findings board refreshes itself on the engagement's events (a push,
// an edit, a state change elsewhere) with its filters kept, and brings the
// progress panel along; it holds off while rows are picked or more loaded.
func TestFindingsBoardLive(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme?sort=title", nil, nil).Body.String()
	head := between(b, `<div id="findings"`, ">")
	for _, want := range []string{`data-sse-url="/events?eng=acme"`, `hx-get="/e/acme?sort=title"`, "sse:content", "sse:workflow", "sse:resync", "data-sse"} {
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
	// the hold-off is in app.js (htmx evaluates no trigger filter)
	if js := e.do(t, "alice", "GET", staticPrefix()+"/app.js", nil, nil).Body.String(); !strings.Contains(js, "yarsListIdle") || !strings.Contains(js, "htmx:beforeRequest") {
		t.Fatal("app.js lacks the list's hold-off (yarsListIdle on htmx:beforeRequest)")
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

// The export Findings panel has its head before its table (reading and
// keyboard order), with the ticked count rendered by the server.
func TestExportPickHeadFirst(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/e/acme/export", nil, nil).Body.String()
	panel := between(b, `<section class="panel compact pickpanel">`, "</section>")
	head, table := strings.Index(panel, `class="panelhead"`), strings.Index(panel, "<table")
	if head < 0 || table < 0 || head > table {
		t.Fatalf("pick panel order:\n%s", panel)
	}
	if !regexp.MustCompile(`class="mono selof" data-of="\d+">\d+ of \d+</span>`).MatchString(panel) {
		t.Fatalf("no count in the head:\n%s", panel)
	}
	css := e.do(t, "dora", "GET", staticPrefix()+"/style.css", nil, nil).Body.String()
	if strings.Contains(css, "order: -1") && strings.Contains(between(css, ".pickpanel > .panelhead", "}"), "order") {
		t.Fatal("the head is still moved by CSS order")
	}
	// boxes restored by the browser (reload, back/forward) are recounted
	js := e.do(t, "dora", "GET", staticPrefix()+"/app.js", nil, nil).Body.String()
	for _, want := range []string{"addEventListener('DOMContentLoaded', yarsPickCountAll)", "addEventListener('pageshow', yarsPickCountAll)", "addEventListener('htmx:afterSettle', yarsPickCountAll)"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
}

// A failed login keeps the username (never the password) and focuses the
// password field.
func TestLoginKeepsUsername(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"wrong-secret"}}, nil)
	b := rec.Body.String()
	if rec.Code != http.StatusUnauthorized || !strings.Contains(b, `name="username" value="alice"`) || strings.Contains(b, "wrong-secret") {
		t.Fatalf("%d:\n%s", rec.Code, b)
	}
	if !regexp.MustCompile(`name="password"[^>]*autofocus`).MatchString(b) || regexp.MustCompile(`name="username"[^>]*autofocus`).MatchString(b) {
		t.Fatalf("focus:\n%s", b)
	}
	if b := e.do(t, "", "GET", "/login", nil, nil).Body.String(); !regexp.MustCompile(`name="username" value=""[^>]*autofocus`).MatchString(b) {
		t.Fatalf("empty login form:\n%s", b)
	}
}

// Every inbox column has a header, the action column too.
func TestInboxActionHeader(t *testing.T) {
	e := setup(t)
	for _, u := range []string{"alice", "dora"} {
		b := e.do(t, u, "GET", "/inbox", nil, nil).Body.String()
		if strings.Contains(b, `<th class="c-go"></th>`) || !strings.Contains(b, `<th class="c-go">Action</th>`) {
			t.Errorf("%s: action column without a header", u)
		}
	}
}

// The conflict view shows each side against the text both started from:
// the base line removed, each side's own line added.
func TestConflictDiffAgainstBase(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	alice := config.User{Username: "alice", Role: "pentester"}
	if err := st.UpdateSection("acme", "F-001-sql-injection", "Impact", "base line", "", alice); err != nil {
		t.Fatal(err)
	}
	ref, _ := st.Finding("acme", "F-001-sql-injection")
	body, _ := ref.F.Section("Impact")
	base := store.BodyHash(body)
	if err := st.UpdateSection("acme", "F-001-sql-injection", "Impact", "their line", "", alice); err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, "alice", "POST", "/e/acme/f/F-001-sql-injection/s/Impact", url.Values{"body": {"my line"}, "base": {base}}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("code %d", rec.Code)
	}
	diff := between(rec.Body.String(), `class="cdiff`, "</section>")
	cols := strings.SplitN(diff, `class="ccol"`, 3)
	if len(cols) != 3 {
		t.Fatalf("diff:\n%s", diff)
	}
	for i, want := range []string{"my line", "their line"} {
		col := cols[i+1]
		if !regexp.MustCompile(`class="ln del">.*?base line`).MatchString(col) || !regexp.MustCompile(`class="ln add">.*?`+want).MatchString(col) {
			t.Errorf("column %d lacks the base removed and %q added:\n%s", i, want, col)
		}
	}
}

// Admin activity: disabling and enabling an account carry no "on"/"off"
// detail, which read backwards next to the action.
func TestAuditDisableEnableDetail(t *testing.T) {
	e := setup(t)
	e.do(t, "dora", "POST", "/admin/users/alice/disabled", url.Values{"on": {"1"}}, nil)
	e.do(t, "dora", "POST", "/admin/users/alice/disabled", url.Values{}, nil)
	l, _ := e.srv.Store.DB().AuditLog(10)
	seen := map[string]bool{}
	for _, a := range l {
		if a.Action == "user.disable" || a.Action == "user.enable" {
			seen[a.Action] = true
			if a.Detail != "" {
				t.Errorf("%s detail %q", a.Action, a.Detail)
			}
		}
	}
	if !seen["user.disable"] || !seen["user.enable"] {
		t.Fatalf("audit %+v", l)
	}
	// a row stored the old way reads right on the page too
	e.srv.Store.DB().Audit("dora", "user.disable", "bob", "on")
	b := e.do(t, "dora", "GET", "/admin/activity", nil, nil).Body.String()
	if row := between(b, ">user.disable<", "</tr>"); strings.Contains(row, ">on<") || strings.Contains(row, ">off<") {
		t.Fatalf("activity row: %s", row)
	}
}

// A finding's tab and its history's tab name the finding; the site has a
// favicon (no 404 on every first load).
func TestTabTitlesAndFavicon(t *testing.T) {
	e := setup(t)
	for p, want := range map[string]string{
		"/e/acme/f/001":         "<title>F-001 SQL injection · YARS</title>",
		"/e/acme/f/001/history": "<title>F-001 history · YARS</title>",
	} {
		if b := e.do(t, "alice", "GET", p, nil, nil).Body.String(); !strings.Contains(b, want) {
			t.Errorf("%s: no %s", p, want)
		}
	}
	b := e.do(t, "alice", "GET", "/e/acme/f/001", nil, nil).Body.String()
	if !strings.Contains(b, `<link rel="icon" type="image/svg+xml" href="`+staticPrefix()+`/favicon.svg">`) {
		t.Error("no icon link")
	}
	if rec := e.do(t, "alice", "GET", staticPrefix()+"/favicon.svg", nil, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "<svg") {
		t.Errorf("favicon.svg %d", rec.Code)
	}
	if rec := e.do(t, "", "GET", "/favicon.ico", nil, nil); rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != staticPrefix()+"/favicon.svg" {
		t.Errorf("favicon.ico %d %q", rec.Code, rec.Header().Get("Location"))
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
