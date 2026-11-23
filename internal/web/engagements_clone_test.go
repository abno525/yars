package web

import (
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"yars/internal/auth"
	"yars/internal/gitrepo"
	"yars/internal/gitserve"
	"yars/internal/store"
)

// The engagements list's Clone panel is a compact panel (small uppercase
// heading) with the commands full width under it (board 2.3).
func TestEngagementsClonePanel(t *testing.T) {
	e := setup(t)
	e.srv.Git = http.NotFoundHandler()
	b := e.do(t, "dora", "GET", "/engagements", nil, nil).Body.String()
	if !strings.Contains(b, `data-copy="clone-cmd"`) {
		t.Fatal("no clone panel")
	}
	for _, want := range []string{`<section class="panel compact">`, `<pre class="flush"><code id="clone-cmd">`, `class="btn secondary sm w96" data-copy="clone-cmd"`} {
		if !strings.Contains(b, want) {
			t.Errorf("clone panel lacks %s", want)
		}
	}
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	if !strings.Contains(css, ".panel pre.flush { margin: 0; padding: 16px 20px; }") {
		t.Error("style.css lacks the full-width pre")
	}
}

var cloneCmdRe = regexp.MustCompile(`(?s)<code id="clone-cmd">(.*?)</code>`)

// cloneCmd is the Clone panel's command as the page shows it (the text the
// Copy button copies).
func cloneCmd(t *testing.T, page string) string {
	t.Helper()
	m := cloneCmdRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("no clone command:\n%s", page)
	}
	return html.UnescapeString(m[1])
}

// The Clone panel gives each account a command that works for it. git
// stops a recursive clone at the first engagement the account may not fetch,
// so only an account that sees every engagement (a director, an admin, every
// account of the simple workflow) clones recursively; a team member checks
// out their engagements by path, and an account on no team gets the main
// repository alone.
func TestEngagementsCloneCommandPerRole(t *testing.T) {
	e := setup(t)
	e.srv.Git = http.NotFoundHandler()
	a := gitrepo.Author{Name: "dora", Email: "dora@yars.local"}
	if err := e.srv.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, a); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.DB().AddMembers("beta", "bob"); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.DB().RemoveMember("acme", "carol"); err != nil {
		t.Fatal(err)
	}
	cmd := func(e *env, user string) string {
		t.Helper()
		return cloneCmd(t, e.do(t, user, "GET", "/engagements", nil, nil).Body.String())
	}
	all := "git clone --recurse-submodules http://example.com/git/yars && cd yars\ngit submodule foreach -q git switch -q main"
	for user, want := range map[string]string{
		"dora":  all,
		"alice": "git clone http://example.com/git/yars && cd yars\ngit submodule update --init engagements/acme\ngit submodule foreach -q git switch -q main",
		"bob":   "git clone http://example.com/git/yars && cd yars\ngit submodule update --init engagements/acme engagements/beta\ngit submodule foreach -q git switch -q main",
		"carol": "git clone http://example.com/git/yars",
	} {
		if got := cmd(e, user); got != want {
			t.Errorf("%s:\n%s\nwant\n%s", user, got, want)
		}
	}
	// the simple workflow: every account sees every engagement
	s := setupSimple(t)
	s.srv.Git = http.NotFoundHandler()
	if got := cmd(s, "ben"); got != all {
		t.Errorf("simple workflow, ben:\n%s\nwant\n%s", got, all)
	}
}

// Developers › Git gives the main clone per account too, on one line: the
// recursive clone only to an account that sees every engagement.
func TestDeveloperDocsMainClonePerRole(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.DB().RemoveMember("acme", "carol"); err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`<span class="flabel">([^<]*)</span>\s*<div class="codeline"><code id="git-all">([^<]*)</code>`)
	for user, want := range map[string][2]string{
		"dora":  {"Everything", "git clone --recurse-submodules http://dora@example.com/git/yars findings"},
		"alice": {"Your engagements", "git clone http://alice@example.com/git/yars findings &amp;&amp; git -C findings submodule update --init engagements/acme"},
		"carol": {"Your engagements", "git clone http://carol@example.com/git/yars findings"},
	} {
		m := re.FindStringSubmatch(e.do(t, user, "GET", "/docs/git", nil, nil).Body.String())
		if m == nil || m[1] != want[0] || m[2] != want[1] {
			t.Errorf("%s: %q, want %q", user, m, want)
		}
	}
}

// The Clone panel's command, run as the page shows it with real git against
// the git server, gives a pentester on one of two engagements a main clone
// with that engagement checked out on main and the other left out (a
// recursive clone aborts on it: "Failed to clone 'engagements/beta' a second
// time"). Pulling such a clone later touches only its engagements.
func TestEngagementsCloneCommandRuns(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	a := gitrepo.Author{Name: "dora", Email: "dora@yars.local"}
	if err := st.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, a); err != nil {
		t.Fatal(err) // alice is on acme's team only
	}
	r, err := gitrepo.Open(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	gs := &gitserve.Server{Repo: r, Auth: e.srv.Auth, CanSee: st.CanSee, Sync: st.SyncPointers, Invalidate: st.Invalidate}
	if err := gs.Setup(); err != nil {
		t.Fatal(err)
	}
	e.srv.Git = gs.Handler()
	e.h = e.srv.Handler()
	srv := httptest.NewServer(e.h)
	// lets the server go once closed (TestFinishedTestsLetTheirServerGo)
	t.Cleanup(func() { srv.Close(); srv = nil })

	req, _ := http.NewRequest("GET", srv.URL+"/engagements", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["alice"]})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var page strings.Builder
	_, err = io.Copy(&page, resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("engagements page: %d %v", resp.StatusCode, err)
	}
	text := cloneCmd(t, page.String())

	// git signs in as alice from a credential store, as a saved login would:
	// the command stays as the page shows it
	home := t.TempDir()
	creds := filepath.Join(home, "creds")
	if err := os.WriteFile(creds, []byte(strings.Replace(srv.URL, "http://", "http://alice:pw@", 1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitconfig := filepath.Join(home, ".gitconfig")
	if err := os.WriteFile(gitconfig, []byte("[credential]\n\thelper = store --file="+creds+"\n[advice]\n\tdetachedHead = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitEnv := append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+home, "GIT_CONFIG_GLOBAL="+gitconfig, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	work := t.TempDir()
	sh := exec.Command("sh", "-e", "-c", text)
	sh.Dir, sh.Env = work, gitEnv
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("the panel's command failed: %v\n%s\n%s", err, text, out)
	}
	clone := filepath.Join(work, "yars")
	git := func(dir string, args ...string) (string, error) {
		c := exec.Command("git", append([]string{"-C", dir}, args...)...)
		c.Env = gitEnv
		out, err := c.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	acme := filepath.Join(clone, "engagements", "acme")
	if _, err := os.Stat(filepath.Join(acme, "engagement.yaml")); err != nil {
		t.Fatal("acme is not checked out")
	}
	if b, err := git(acme, "branch", "--show-current"); err != nil || b != "main" {
		t.Fatalf("acme is on %q (%v), not main", b, err)
	}
	checkedOut := func(id string) bool {
		_, err := os.Stat(filepath.Join(clone, "engagements", id, "engagement.yaml"))
		return err == nil
	}
	if checkedOut("beta") {
		t.Fatal("beta, which alice is not on, is checked out")
	}

	run := func(args ...string) {
		t.Helper()
		if out, err := git(clone, args...); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
		}
	}
	er, _ := gitrepo.Open(filepath.Join(e.dir, "engagements", "acme"))
	// moved: a finding in acme and one in beta move their pointers
	moved := func() string {
		t.Helper()
		for _, eng := range []string{"acme", "beta"} {
			if _, err := st.CreateFinding(eng, "XSS", a); err != nil {
				t.Fatal(err)
			}
		}
		h, _ := er.Head()
		return h
	}
	at := func(want, branch string) {
		t.Helper()
		h, _ := git(acme, "rev-parse", "HEAD")
		b, _ := git(acme, "branch", "--show-current")
		if h != want || b != branch {
			t.Fatalf("acme at %s on %q, want %s on %q", h, b, want, branch)
		}
	}
	// the pull docs/git.md gives: the top folder, then each engagement on
	// its main
	head := moved()
	run("pull", "-q")
	run("submodule", "foreach", "-q", "git", "pull", "-q")
	at(head, "main")
	// a pull with submodules fetches and checks out (detached) only the
	// clone's own engagements; switched back, main is still the old one
	head = moved()
	run("pull", "-q", "--recurse-submodules")
	run("submodule", "update")
	at(head, "")
	run("submodule", "foreach", "-q", "git", "switch", "-q", "main")
	if sb, _ := git(acme, "status", "-sb"); !strings.Contains(sb, "[behind 1]") {
		t.Fatalf("acme after the switch:\n%s", sb)
	}
	run("submodule", "foreach", "-q", "git", "pull", "-q")
	at(head, "main")
	if checkedOut("beta") {
		t.Fatal("a pull checked out beta")
	}

	// a new engagement arrives as an empty folder and is checked out by its
	// path; without one, git stops at beta and every later pull tries it
	// again, until it is deinitialized
	if err := st.CreateEngagement(store.Engagement{ID: "gamma", Name: "Gamma"}, a); err != nil {
		t.Fatal(err)
	}
	if err := st.DB().AddMembers("gamma", "alice"); err != nil {
		t.Fatal(err)
	}
	run("pull", "-q", "--recurse-submodules")
	if checkedOut("gamma") {
		t.Fatal("a pull checked out the new engagement")
	}
	run("submodule", "update", "--init", "engagements/gamma")
	run("submodule", "foreach", "-q", "git", "switch", "-q", "main")
	if b, _ := git(filepath.Join(clone, "engagements", "gamma"), "branch", "--show-current"); !checkedOut("gamma") || b != "main" {
		t.Fatalf("gamma: checked out %v, on %q", checkedOut("gamma"), b)
	}
	if out, err := git(clone, "submodule", "update", "--init"); err == nil {
		t.Fatalf("submodule update --init of every engagement got beta:\n%s", out)
	}
	if out, err := git(clone, "pull", "-q", "--recurse-submodules"); err == nil {
		t.Fatalf("a pull after beta was registered did not try it:\n%s", out)
	}
	run("submodule", "deinit", "-q", "engagements/beta")
	run("pull", "-q", "--recurse-submodules")
}
