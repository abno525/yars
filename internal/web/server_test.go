package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"weak"

	"golang.org/x/crypto/bcrypt"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/store"
)

var (
	hashOnce sync.Once
	pwHash   string
	// paralleled is the tests setup has made parallel
	paralleled sync.Map
)

type env struct {
	srv  *Server
	h    http.Handler
	dir  string
	toks map[string]string
	// log keeps what the server, its store and its accounts log
	log *logs.Recorder
	// parallel is set by setup: the test runs beside other parallel tests
	parallel bool
}

// setup is a server of its own (temp dirs, database, git repos) for a test
// that runs in parallel with the other setup tests. Parallel tests only start
// once every serial test has finished, so a serial test never shares the
// process with them.
func setup(t *testing.T) *env {
	t.Helper()
	parallelOnce(t)
	e := newEnv(t)
	e.parallel = true
	return e
}

// parallelOnce makes t parallel the first time a setup asks (a test may build
// several servers; t.Parallel may be called once) and forgets t when it ends.
func parallelOnce(t *testing.T) {
	if _, again := paralleled.LoadOrStore(t, true); !again {
		t.Cleanup(func() { paralleled.Delete(t) })
		t.Parallel()
	}
}

// setupSerial is setup for a test that must not run beside others: it counts
// git processes (gitrepo.Spawned is one counter per process), writes scripts
// and runs them (a fork in a parallel test can hold the file open for
// writing: ETXTBSY, golang/go#22315), sets env vars, or has a time limit.
func setupSerial(t *testing.T) *env {
	t.Helper()
	return newEnv(t)
}

// A finished test lets its server go. testing keeps every parallel test, and
// the cleanups it registered, until the whole package has run, so a cleanup
// holding the server kept it (store, database, index, pages): 16 MB a test,
// 6 GB over the package, more than a CI runner has. setup also forgets the
// test in paralleled.
func TestFinishedTestsLetTheirServerGo(t *testing.T) {
	var kept []*testing.T // as testing keeps them
	var servers []weak.Pointer[Server]
	for _, c := range []struct {
		name, user string
		mk         func(*testing.T) *env
	}{{"setup", "dora", setup}, {"serial", "dora", setupSerial}, {"simple", "anna", setupSimple}} {
		// a parallel subtest has ended when its group's Run returns
		t.Run(c.name, func(t *testing.T) {
			t.Run("test", func(t *testing.T) {
				kept = append(kept, t)
				e := c.mk(t)
				// the server builds its pages
				if rec := e.do(t, c.user, "GET", "/e/acme/f/F-001-sql-injection", nil, nil); rec.Code != 200 {
					t.Fatalf("code %d", rec.Code)
				}
				servers = append(servers, weak.Make(e.srv))
			})
		})
	}
	runtime.GC()
	runtime.GC()
	for i, w := range servers {
		if w.Value() != nil {
			t.Errorf("%s: its server is still live", kept[i].Name())
		}
		if _, held := paralleled.Load(kept[i]); held {
			t.Errorf("%s: still in paralleled", kept[i].Name())
		}
	}
	runtime.KeepAlive(kept)
}

// serialOnly fails a parallel test that does something only a serial one may.
func (e *env) serialOnly(t *testing.T, what string) {
	t.Helper()
	if e.parallel {
		t.Fatalf("%s: use setupSerial, not setup", what)
	}
}

func newEnv(t *testing.T) *env {
	t.Helper()
	lg, logged := logs.NewRecorder()
	e := newEnvLog(t, lg)
	e.log = logged
	return e
}

// newEnvLog is newEnv with the logger the server, its store and its
// accounts write to (newEnv keeps the records; e.log is nil here).
func newEnvLog(t *testing.T, lg *slog.Logger) *env {
	t.Helper()
	// minimum cost: a login check reads the cost from the stored hash, so the
	// four logins below are fast; production hashes stay at 12
	hashOnce.Do(func() {
		h, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
		pwHash = string(h)
	})
	dir := t.TempDir()
	r, err := gitrepo.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	// each cleanup lets go of what it closed: testing keeps the test, and so
	// its cleanups, until the whole package has run
	// (TestFinishedTestsLetTheirServerGo)
	t.Cleanup(func() { d.Close(); d = nil })
	st := store.New(r, cfg, d)
	st.Logger = lg
	a := gitrepo.Author{Name: "alice", Email: "alice@yars.local"}
	if err := st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME Web"}, a); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFinding("acme", "SQL injection", a); err != nil {
		t.Fatal(err)
	}
	users := []config.User{
		{Username: "alice", Role: "pentester", PasswordHash: pwHash},
		{Username: "bob", Role: "reviewer", PasswordHash: pwHash},
		{Username: "dora", Role: "director", PasswordHash: pwHash, IsAdmin: true},
		{Username: "carol", Role: "reviewer", PasswordHash: pwHash},
	}
	for _, u := range users {
		if err := d.AddUser(u); err != nil {
			t.Fatal(err)
		}
	}
	// everyone is on the team of the test engagement (dora directs)
	if err := d.AddMembers("acme", "alice", "bob", "carol"); err != nil {
		t.Fatal(err)
	}
	au := auth.New(d)
	au.Logger = lg
	s := &Server{Store: st, Index: index.New(st, r), Auth: au, Cfg: cfg, Logger: lg}
	e := &env{srv: s, h: s.Handler(), dir: dir, toks: map[string]string{}}
	t.Cleanup(func() { s.Close(); s = nil })
	for _, u := range users {
		tok, ok := au.Login(u.Username, "pw")
		if !ok {
			t.Fatal("login failed")
		}
		e.toks[u.Username] = tok
	}
	return e
}

func (e *env) do(t *testing.T, user, method, path string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if user != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks[user]})
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *env) authorOf(u config.User) gitrepo.Author { return store.AuthorOf(u) }

func (e *env) lastCommit(t *testing.T) string {
	t.Helper()
	// finding commits go to the engagement's own repository
	out, err := exec.Command("git", "-C", filepath.Join(e.dir, "engagements", "acme"), "log", "-1", "--format=%an|%s").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestCloneHint(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", "/", nil, nil).Body.String(); strings.Contains(b, "git clone") {
		t.Fatal("hint shown without git endpoint")
	}
	e.srv.Git = http.NotFoundHandler()
	// a team member checks out their engagements by path (TestEngagementsCloneCommandPerRole)
	if b := e.do(t, "alice", "GET", "/", nil, nil).Body.String(); !strings.Contains(b, "git clone http://example.com/git/yars") {
		t.Fatalf("no clone hint:\n%s", b)
	}
	// an engagement can be cloned on its own
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); !strings.Contains(b, "git clone http://example.com/git/e/acme") {
		t.Fatalf("no engagement clone hint:\n%s", b)
	}
}

func TestEngagementTable(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "GET", "/e/acme", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	b := rec.Body.String()
	if !strings.Contains(b, "SQL injection") || !strings.Contains(b, "F-001") || !strings.Contains(b, "ACME Web") {
		t.Fatalf("body missing content:\n%s", b)
	}
}

func TestTablePartialOnHX(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "GET", "/e/acme?sort=status", nil, map[string]string{"HX-Request": "true"})
	b := rec.Body.String()
	if rec.Code != 200 || strings.Contains(b, "<html") || !strings.Contains(b, "F-001") {
		t.Fatalf("code %d body:\n%s", rec.Code, b)
	}
}

func TestFindingPageSections(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "GET", "/e/acme/f/F-001-sql-injection", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	for _, s := range config.Default().Sections {
		if !strings.Contains(rec.Body.String(), "<h2>"+s+"</h2>") {
			t.Fatalf("missing section %s", s)
		}
	}
}

func TestTraversal404(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/e/..%2F..%2Fetc/f/x", "/e/acme/f/..%2F..%2F..", "/e/nope"} {
		if rec := e.do(t, "alice", "GET", p, nil, nil); rec.Code != 404 {
			t.Fatalf("%s: code %d", p, rec.Code)
		}
	}
}

func TestUnauthedRedirect(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "", "GET", "/", nil, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("code %d loc %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestLoginFlow(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"pw"}}, nil)
	if rec.Code != http.StatusSeeOther || len(rec.Result().Cookies()) == 0 {
		t.Fatalf("code %d", rec.Code)
	}
	rec = e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"bad"}}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login code %d", rec.Code)
	}
}

func TestMarkdownNoRawHTML(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Impact", "<script>alert(1)</script>", "", gitrepo.Author{Name: "x", Email: "x@x"}); err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, "alice", "GET", "/e/acme/f/F-001-sql-injection", nil, nil)
	if strings.Contains(rec.Body.String(), "<script>alert(1)") {
		t.Fatal("raw HTML rendered")
	}
}

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

// The gutter kept for the scrollbar shows the canvas, which takes the
// root's background: on a page too short to scroll it stood as a 17px strip
// of page colour beside the top bar. A gradient on the root does not reach
// it: Chrome paints only the root's background colour into the gutter (the
// final test's browser check, with the root's colour set to red). Where
// there is a top bar the page's scrollbar is always shown, so a page too
// short to scroll has the same track beside the bar as one that scrolls;
// the gutter was kept already, so no width changes. The login page has no
// bar.
func TestGutterBesideTopBar(t *testing.T) {
	e := setup(t)
	css := e.do(t, "alice", "GET", staticPrefix()+"/style.css", nil, nil).Body.String()
	if rule := between(css, "\nhtml:has(.topbar) {", "}"); rule != "\nhtml:has(.topbar) { overflow-y: scroll; " {
		t.Fatalf("html:has(.topbar) rule: %q", rule)
	}
	if b := e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String(); !strings.Contains(b, `<header class="topbar">`) {
		t.Fatal("no top bar on a signed-in page")
	}
	if b := e.do(t, "", "GET", "/login", nil, nil).Body.String(); strings.Contains(b, `class="topbar"`) {
		t.Fatal("the login page has a top bar")
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
