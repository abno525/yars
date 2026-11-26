package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/store"
)

// outsider adds eve, a pentester on no team.
func (e *env) outsider(t *testing.T) {
	t.Helper()
	if err := e.srv.Store.DB().AddUser(config.User{Username: "eve", Role: "pentester", PasswordHash: pwHash}); err != nil {
		t.Fatal(err)
	}
	tok, ok := e.srv.Auth.Login("eve", "pw")
	if !ok {
		t.Fatal("login eve")
	}
	e.toks["eve"] = tok
}

// lead creates a note on acme's board as user.
func (e *env) lead(t *testing.T, user, title, host, state string) store.Note {
	t.Helper()
	u, _ := e.srv.Auth.Lookup(user)
	n, err := e.srv.Store.CreateNote("acme", title, host, state, "First look at **"+title+"**.", u)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTeamBoardPage(t *testing.T) {
	e := setup(t)
	e.lead(t, "alice", "Verbose stack trace", "api.acme.test", "open")
	e.lead(t, "bob", "Subdomains", "acme.test", "info")
	rec := e.do(t, "carol", "GET", "/e/acme/board", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("board %d", rec.Code)
	}
	b := rec.Body.String()
	tabs := tabsOf(t, b)
	// Team board sits after Findings, on, with the unseen count (orange):
	// the note opened here is seen already
	if !strings.Contains(tabs, `href="/e/acme/board" aria-current="page">Team board <span class="badge">1</span>`) ||
		strings.Index(tabs, "/e/acme/board") > strings.Index(tabs, "/e/acme/overview") {
		t.Fatalf("tabs:\n%s", tabs)
	}
	for _, want := range []string{
		`<th class="c-lid">ID</th>`, `<th class="c-lstate">State</th>`, `<th class="c-lby">By</th>`, `>Replies</th>`, `>Activity ↓</th>`,
		`All · 2`, `Open · 1`, `Info · 1`, `Dismissed · 0`, `L-002`, `api.acme.test`, `<span class="tag lead-info">Info</span>`,
		`data-sse-url="/events?eng=acme&amp;f=board"`, `hx-trigger="sse:board, sse:resync, sse:poll"`,
		`href="/e/acme/board?new=1"`, `>New lead</a>`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("board lacks %q", want)
		}
	}
	// the newest note is open in the thread panel
	if !strings.Contains(b, `<h2 title="Subdomains">Subdomains</h2>`) || !strings.Contains(b, `<strong>Subdomains</strong>`) {
		t.Fatalf("thread:\n%s", b)
	}
	noInline(t, "/e/acme/board", b)
	// opening it marked it seen: one left
	if b := e.do(t, "carol", "GET", "/e/acme", nil, nil).Body.String(); !strings.Contains(tabsOf(t, b), `Team board <span class="badge">1</span>`) {
		t.Fatalf("after one opened:\n%s", tabsOf(t, b))
	}
	e.do(t, "carol", "GET", "/e/acme/board?n=L-001", nil, nil)
	if b := e.do(t, "carol", "GET", "/e/acme", nil, nil).Body.String(); !strings.Contains(tabsOf(t, b), `Team board <span class="badge0">0</span>`) {
		t.Fatalf("after both opened:\n%s", tabsOf(t, b))
	}
	// filter and search keep the URL state
	b = e.do(t, "carol", "GET", "/e/acme/board?state=info&q=sub", nil, map[string]string{"HX-Request": "true"}).Body.String()
	if strings.Contains(b, "<html") || !strings.Contains(b, "Subdomains") || strings.Contains(b, ">Verbose stack trace<") || !strings.Contains(b, `class="on"`) {
		t.Fatalf("filtered:\n%s", b)
	}
	// a selected note outside the filter stays selected
	b = e.do(t, "carol", "GET", "/e/acme/board?state=info&n=L-001", nil, nil).Body.String()
	if !strings.Contains(b, `<h2 title="Verbose stack trace">`) {
		t.Fatal("selection lost to the filter")
	}
	for _, bad := range []string{"?n=L-009", "?n=x", "/n/9"} {
		p := "/e/acme/board" + bad
		if rec := e.do(t, "carol", "GET", p, nil, nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
}

// Without a database (content only) there is no board: 404, not 500.
func TestTeamBoardNoDB(t *testing.T) {
	e := setup(t)
	s := &Server{Store: store.New(e.srv.Store.Repo(), config.Default(), nil)}
	rec := httptest.NewRecorder()
	s.withBoard(func(http.ResponseWriter, *http.Request) { t.Fatal("handler ran") })(rec, httptest.NewRequest("GET", "/e/acme/board", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no database: %d", rec.Code)
	}
}

func TestTeamBoardEmpty(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme/board", nil, nil).Body.String()
	if !strings.Contains(b, `<thead>`) || !strings.Contains(b, `<tr class="emptyrow"><td colspan="6">—</td></tr>`) || !strings.Contains(b, `class="tbthread empty"`) {
		t.Fatalf("empty board:\n%s", b)
	}
	if !strings.Contains(tabsOf(t, b), `Team board <span class="badge0">0</span>`) {
		t.Fatal("no zero badge")
	}
}

func TestTeamBoardCreate(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme/board?new=1", nil, nil).Body.String()
	if !strings.Contains(b, `hx-post="/e/acme/board"`) || !strings.Contains(b, `name="title"`) || !strings.Contains(b, `name="text"`) {
		t.Fatalf("new lead form:\n%s", b)
	}
	rec := e.do(t, "alice", "POST", "/e/acme/board", url.Values{"title": {""}, "text": {"x"}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `<span class="ferr" id="err-title">Required</span>`) {
		t.Fatalf("no title %d:\n%s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "alice", "POST", "/e/acme/board", url.Values{"title": {"JWT alg none"}, "host": {"api.acme.test"}, "state": {"open"}, "text": {"Token with `alg none`."}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `<h2 title="JWT alg none">`) || !strings.Contains(rec.Body.String(), "<code>alg none</code>") {
		t.Fatalf("create %d:\n%s", rec.Code, rec.Body.String())
	}
}

// Everything on the board goes through the team gate, and a note number
// is only ever looked up in the engagement of the URL.
func TestTeamBoardAccess(t *testing.T) {
	e := setup(t)
	e.outsider(t)
	e.lead(t, "alice", "ours", "", "open")
	dora, _ := e.srv.Auth.Lookup("dora")
	if err := e.srv.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, e.authorOf(dora)); err != nil {
		t.Fatal(err)
	}
	e.srv.Store.DB().AddMembers("beta", "eve")
	eve, _ := e.srv.Auth.Lookup("eve")
	e.srv.Store.CreateNote("beta", "theirs 1", "", "open", "secret one", eve)
	e.srv.Store.CreateNote("beta", "theirs 2", "", "open", "secret two", eve)
	for _, p := range []string{"/e/acme/board", "/e/acme/board?n=L-001", "/e/acme/board/n/L-001"} {
		if rec := e.do(t, "eve", "GET", p, nil, nil); rec.Code != http.StatusNotFound {
			t.Errorf("outsider GET %s: %d", p, rec.Code)
		}
	}
	for _, act := range []string{"post", "state", "dismiss", "severity", "dup", "finding"} {
		p := "/e/acme/board/n/L-001/" + act
		if rec := e.do(t, "eve", "POST", p, url.Values{"text": {"x"}}, nil); rec.Code != http.StatusNotFound {
			t.Errorf("outsider POST %s: %d", p, rec.Code)
		}
	}
	if rec := e.do(t, "eve", "POST", "/e/acme/board", url.Values{"title": {"x"}, "text": {"y"}}, nil); rec.Code != http.StatusNotFound {
		t.Errorf("outsider create: %d", rec.Code)
	}
	// beta's L-002 through acme's URL: no such note here
	rec := e.do(t, "alice", "GET", "/e/acme/board?n=L-002", nil, nil)
	if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "secret two") {
		t.Fatalf("cross engagement %d", rec.Code)
	}
	// pentester, reviewer and director all write on the board
	for i, u := range []string{"alice", "bob", "dora"} {
		rec := e.do(t, u, "POST", "/e/acme/board/n/L-001/post", url.Values{"text": {"from " + u}}, nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "from "+u) {
			t.Fatalf("%d %s post %d", i, u, rec.Code)
		}
	}
}

func TestTeamBoardActions(t *testing.T) {
	e := setup(t)
	e.lead(t, "alice", "S3 listing", "https://bucket.acme.test/", "open")
	post := func(user, act string, v url.Values) (int, string) {
		t.Helper()
		rec := e.do(t, user, "POST", "/e/acme/board/n/L-001/"+act, v, nil)
		return rec.Code, rec.Body.String()
	}
	// Make finding only from Confirmed or Info
	if code, b := post("bob", "finding", url.Values{}); code != http.StatusBadRequest {
		t.Fatalf("make from open %d:\n%s", code, b)
	}
	if code, _ := post("bob", "state", url.Values{"from": {"open"}, "to": {"analyzing"}}); code != 200 {
		t.Fatalf("analyzing %d", code)
	}
	// a stale click: the panel comes back with the note as it is
	if code, b := post("alice", "state", url.Values{"from": {"open"}, "to": {"confirmed"}}); code != http.StatusConflict || !strings.Contains(b, `<span class="tag lead-analyzing">Analyzing</span>`) {
		t.Fatalf("stale %d:\n%s", code, b)
	}
	if code, b := post("bob", "dismiss", url.Values{"from": {"analyzing"}, "reason": {""}}); code != http.StatusBadRequest || !strings.Contains(b, "Reason: required") {
		t.Fatalf("dismiss without reason %d:\n%s", code, b)
	}
	if code, b := post("bob", "severity", url.Values{"severity": {"high"}}); code != 200 || !strings.Contains(b, `<span class="sevchip">Severity · High</span>`) {
		t.Fatalf("severity %d:\n%s", code, b)
	}
	if code, _ := post("bob", "severity", url.Values{"severity": {"apocalyptic"}}); code != http.StatusBadRequest {
		t.Fatalf("bad severity %d", code)
	}
	// Duplicate of is gone from the board, its action too
	if code, _ := post("bob", "dup", url.Values{"dup": {"l-2"}}); code != http.StatusNotFound {
		t.Fatalf("dup %d", code)
	}
	if code, _ := post("bob", "state", url.Values{"from": {"analyzing"}, "to": {"confirmed"}}); code != 200 {
		t.Fatalf("confirmed %d", code)
	}
	code, b := post("bob", "finding", url.Values{})
	if code != 200 || !strings.Contains(b, `href="/e/acme/f/002"`) || !strings.Contains(b, `<strong>Finding</strong>`) {
		t.Fatalf("make finding %d:\n%s", code, b)
	}
	f, err := e.srv.Store.Finding("acme", "002")
	if err != nil || f.F.Meta.Author != "bob" || f.F.Meta.Severity != "high" || f.F.Meta.Title != "S3 listing" {
		t.Fatalf("finding %+v %v", f.F.Meta, err)
	}
	// read only now: every change answers 409, the controls are disabled
	for _, act := range []string{"post", "state", "dismiss", "severity", "finding"} {
		code, _ := post("alice", act, url.Values{"text": {"x"}, "from": {"confirmed"}, "to": {"open"}, "reason": {"r"}, "severity": {"low"}})
		if code != http.StatusConflict {
			t.Errorf("%s on a linked note: %d", act, code)
		}
	}
	b = e.do(t, "alice", "GET", "/e/acme/board?n=L-001", nil, nil).Body.String()
	if !strings.Contains(b, `placeholder="Read-only"`) || strings.Contains(b, `hx-post="/e/acme/board/n/L-001/post"`) {
		t.Fatal("linked note still editable")
	}
}

// A lead's head: no Analysis block and no Duplicate of; the likely severity
// sits right after Set state (disabled the same way when read only). The
// row fits the 518 px the thread column gives it (136 + 96 + 112 + 136 and
// three 8 px gaps); a refused change's message has its own line under it.
func TestTeamBoardHeadSeverity(t *testing.T) {
	e := setup(t)
	e.lead(t, "alice", "S3 listing", "", "open")
	b := e.do(t, "bob", "GET", "/e/acme/board?n=L-001", nil, nil).Body.String()
	head := between(b, `<div class="tbacts">`, `class="tbstate`)
	set, sev := strings.Index(head, "Set state ▾</summary>"), strings.Index(head, `<select class="w136" name="severity" aria-label="Likely severity" data-choose><option value="">Severity</option>`)
	if set < 0 || sev < set {
		t.Errorf("severity is not after Set state:\n%s", head)
	}
	if !strings.Contains(head, `<summary class="btn ghost sm w96" aria-keyshortcuts="D">Dismiss</summary>`) || strings.Index(b, `<div class="tbstate" role="status" title=""></div>`) < strings.Index(b, `class="tbsev"`) {
		t.Errorf("Dismiss is not 96 px or the message has no line of its own:\n%s", between(b, `<div class="tbhead">`, `<div class="tbmsgs">`))
	}
	for _, gone := range []string{"tbanalysis", ">Analysis<", `name="dup"`, "Duplicate of", "tbdup"} {
		if strings.Contains(b, gone) {
			t.Errorf("the board still has %s", gone)
		}
	}
	// read only (archived): the select is there, disabled, in the same place
	dora, _ := e.srv.Auth.Lookup("dora")
	e.srv.Store.Archive("acme", dora)
	head = between(e.do(t, "bob", "GET", "/e/acme/board?n=L-001", nil, nil).Body.String(), `<div class="tbacts">`, `class="tbstate`)
	if i := strings.Index(head, `<select class="w136" aria-label="Likely severity" disabled>`); i < strings.Index(head, "Set state ▾") {
		t.Errorf("read only severity:\n%s", head)
	}
}

func TestTeamBoardArchived(t *testing.T) {
	e := setup(t)
	e.lead(t, "alice", "x", "", "info")
	dora, _ := e.srv.Auth.Lookup("dora")
	if err := e.srv.Store.Archive("acme", dora); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/acme/board", nil, nil).Body.String()
	if strings.Contains(b, "hx-post=") || strings.Contains(between(b, "<main>", "</main>"), "?new=1") || !strings.Contains(b, `placeholder="Read-only"`) {
		t.Fatalf("archived board writable:\n%s", b)
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/board", url.Values{"title": {"t"}, "text": {"x"}}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("create: %d", rec.Code)
	}
	for _, act := range []string{"post", "state", "dismiss", "severity", "finding"} {
		rec := e.do(t, "alice", "POST", "/e/acme/board/n/L-001/"+act, url.Values{"text": {"x"}, "from": {"info"}, "to": {"open"}, "reason": {"r"}, "severity": {"low"}}, nil)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: %d", act, rec.Code)
		}
	}
}

func TestTeamBoardEscapes(t *testing.T) {
	e := setup(t)
	x := `<script>alert(1)</script>`
	e.lead(t, "alice", "t"+x, "h"+x, "open")
	e.do(t, "alice", "POST", "/e/acme/board/n/L-001/post", url.Values{"text": {"m" + x}}, nil)
	e.do(t, "alice", "POST", "/e/acme/board/n/L-001/dismiss", url.Values{"from": {"open"}, "reason": {"r" + x}}, nil)
	b := e.do(t, "bob", "GET", "/e/acme/board", nil, nil).Body.String()
	if strings.Contains(b, x) {
		t.Fatalf("raw script on the board:\n%s", b)
	}
	if !strings.Contains(b, "r&lt;script&gt;") {
		t.Fatal("reason not shown escaped")
	}
}

// Board writes reach open pages on their own event, and leave the index
// (and so the findings pages) alone.
func TestTeamBoardLive(t *testing.T) {
	e := setup(t)
	e.lead(t, "alice", "x", "", "open")
	g0, _ := e.srv.Index.Gen()
	sub := e.srv.Events.Subscribe("acme", "board", 8)
	defer e.srv.Events.Unsubscribe(sub)
	e.do(t, "bob", "POST", "/e/acme/board/n/L-001/post", url.Values{"text": {"y"}}, nil)
	select {
	case ev := <-sub.C():
		if ev.Kind != "board" || ev.Fid != "board" || ev.Eng != "acme" {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no board event")
	}
	// a finding tab and the findings list do not hear it
	fsub := e.srv.Events.Subscribe("acme", "F-001", 8)
	defer e.srv.Events.Unsubscribe(fsub)
	esub := e.srv.Events.Subscribe("acme", "", 8)
	defer e.srv.Events.Unsubscribe(esub)
	e.do(t, "bob", "POST", "/e/acme/board/n/L-001/post", url.Values{"text": {"z"}}, nil)
	select {
	case ev := <-fsub.C():
		t.Fatalf("finding tab got %+v", ev)
	case ev := <-esub.C():
		t.Fatalf("engagement stream got %+v", ev)
	case <-time.After(50 * time.Millisecond):
	}
	e.do(t, "bob", "GET", "/e/acme/board?n=L-001", nil, nil)
	if g, _ := e.srv.Index.Gen(); g != g0 {
		t.Fatalf("index generation moved %d -> %d", g0, g)
	}
	// an unchanged board is answered 204
	st, _ := e.srv.Store.NoteStamp("acme")
	rec := e.do(t, "bob", "GET", "/e/acme/board?n=L-001&since="+strconv.FormatInt(st, 10), nil, map[string]string{"HX-Request": "true"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("unchanged %d", rec.Code)
	}
}
