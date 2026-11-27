package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// lintServer is a fake YARS server: it records the lint requests and
// answers each with code and body.
type lintServer struct {
	*httptest.Server
	mu     sync.Mutex
	bodies []string // the POSTs
	auths  []string
	probes int // the GETs that check the login first
	code   int
	body   string
	sleep  time.Duration
}

func newLintServer(t *testing.T, code int, body string) *lintServer {
	t.Helper()
	ls := &lintServer{code: code, body: body}
	ls.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u, p, _ := r.BasicAuth()
		ls.mu.Lock()
		if r.Method == http.MethodGet {
			// the login check: the real server answers 405 after the
			// login, team and token checks; a refused login is 401
			ls.probes++
			code := ls.code
			ls.mu.Unlock()
			if code == http.StatusUnauthorized {
				w.WriteHeader(code)
			} else {
				w.WriteHeader(http.StatusMethodNotAllowed)
			}
			return
		}
		ls.bodies = append(ls.bodies, r.Method+" "+r.URL.RequestURI()+"\n"+string(b))
		ls.auths = append(ls.auths, u+":"+p)
		code, body, sleep := ls.code, ls.body, ls.sleep
		ls.mu.Unlock()
		if sleep > 0 {
			select {
			case <-time.After(sleep):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		io.WriteString(w, body)
	}))
	t.Cleanup(ls.Close)
	return ls
}

func (ls *lintServer) requests() []string {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return append([]string(nil), ls.bodies...)
}

func (ls *lintServer) logins() []string {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return append([]string(nil), ls.auths...)
}

// noUserGit keeps the developer's own git settings and stored logins out.
func noUserGit(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("GIT_CONFIG_GLOBAL", "/dev/null")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
}

// lintClone is an engagement clone whose origin is the server's /git/e/acme
// with alice's login in the URL; F-001's finding.md is staged.
func lintClone(t *testing.T, origin string) string {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=alice", "-c", "user.email=a@a", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	git("remote", "add", "origin", origin)
	write(t, filepath.Join(dir, "engagement.yaml"), "name: ACME\n")
	write(t, filepath.Join(dir, "findings", "F-001-sqli", "finding.md"), "---\nid: F-001\ntitle: SQL injection\n---\n## Description\nstaged\n")
	git("add", "-A")
	return dir
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gitT(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=alice", "-c", "user.email=a@a", "-c", "commit.gpgsign=false"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// withLogin puts user:pw into a server URL.
func withLogin(t *testing.T, raw, user, pw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(user, pw)
	return u.String()
}

func TestLintURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://h:8080/git/e/acme":       "http://h:8080/git/e/acme/lint",
		"https://h/git/e/acme.git":       "https://h/git/e/acme/lint",
		"https://alice:pw@h/git/e/acme/": "https://h/git/e/acme/lint",
	} {
		if got, ok := lintURL(in); !ok || got != want {
			t.Errorf("%s: %q %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"http://h/git/yars", "/tmp/x", "git@h:git/e/acme", "http://h/git/e/", "http://h/git/e/a/b", "ftp://h/git/e/acme"} {
		if got, ok := lintURL(in); ok {
			t.Errorf("%s: %q accepted", in, got)
		}
	}
}

// Review focus 1: what is posted is the index, not the work tree.
func TestLintStagedReadsIndexNotWorktree(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "pw")+"/git/e/acme")
	write(t, filepath.Join(dir, "findings", "F-001-sqli", "finding.md"), "---\nid: F-001\ntitle: changed but not staged\n---\n")
	var out bytes.Buffer
	if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
		t.Fatal(err)
	}
	reqs := ls.requests()
	if len(reqs) != 1 || !strings.HasPrefix(reqs[0], "POST /git/e/acme/lint\n") || !strings.Contains(reqs[0], "title: SQL injection") || strings.Contains(reqs[0], "not staged") {
		t.Fatalf("requests %q", reqs)
	}
}

// The pre-commit check asks for the pattern and built-in rules: a commit
// does not wait for scripts and AI calls. --all asks the server for every
// rule (all=1); the login check before it asks for nothing.
func TestLintStagedAsksForAllOnlyWithAll(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "pw")+"/git/e/acme")
	var out bytes.Buffer
	for _, args := range [][]string{{"--staged"}, {"--staged", "--warn-only"}, {"--staged", "--fast"}} {
		if code, err := cmdLint(append(args, "--data", dir), &out); code != 0 || err != nil {
			t.Fatalf("%v: exit %d %v\n%s", args, code, err, out.String())
		}
	}
	for _, args := range [][]string{{"--staged", "--all"}, {"--staged", "--all", "--warn-only"}} {
		if code, err := cmdLint(append(args, "--data", dir), &out); code != 0 || err != nil {
			t.Fatalf("%v: exit %d %v\n%s", args, code, err, out.String())
		}
	}
	reqs := ls.requests()
	if len(reqs) != 5 {
		t.Fatalf("requests %q", reqs)
	}
	for i, r := range reqs {
		want := "POST /git/e/acme/lint\n"
		if i >= 3 {
			want = "POST /git/e/acme/lint?all=1\n"
		}
		if !strings.HasPrefix(r, want) {
			t.Errorf("request %d: %q", i, r)
		}
	}
}

func TestLintStagedOnlyStagedFindings(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "pw")+"/git/e/acme")
	gitT(t, dir, "commit", "-q", "-m", "first")
	// a second finding left unstaged, a staged file that is not a finding.md,
	// and the first finding staged again
	write(t, filepath.Join(dir, "findings", "F-002-xss", "finding.md"), "---\nid: F-002\ntitle: XSS\n---\n")
	write(t, filepath.Join(dir, "findings", "F-001-sqli", "attachments", "a.txt"), "x")
	write(t, filepath.Join(dir, "findings", "F-001-sqli", "finding.md"), "---\nid: F-001\ntitle: SQL injection again\n---\n")
	gitT(t, dir, "add", "findings/F-001-sqli")
	var out bytes.Buffer
	if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
		t.Fatal(err)
	}
	reqs := ls.requests()
	if len(reqs) != 1 || !strings.Contains(reqs[0], "SQL injection again") {
		t.Fatalf("requests %q", reqs)
	}
	// nothing staged: nothing posted, nothing printed
	gitT(t, dir, "commit", "-q", "-m", "second")
	out.Reset()
	if e, w, err := lintStaged(context.Background(), dir, &out, false); err != nil || e != 0 || w != 0 || out.Len() != 0 || len(ls.requests()) != 1 {
		t.Fatalf("nothing staged: %d %d %v %q", e, w, err, out.String())
	}
}

const twoViolations = `{"violations":[{"rule":"title-dot","level":"error","message":"The title ends with a dot","target":"title","quote":"injection."},{"rule":"impact","level":"warning","message":"Impact is short","target":"section:Impact","quote":""}]}`

func TestLintStagedPrintsViolations(t *testing.T) {
	ls := newLintServer(t, 200, twoViolations)
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "pw")+"/git/e/acme")
	var out bytes.Buffer
	e, w, err := lintStaged(context.Background(), dir, &out, false)
	if err != nil || e != 1 || w != 1 {
		t.Fatalf("%d %d %v", e, w, err)
	}
	want := `findings/F-001-sqli/finding.md error title-dot: The title ends with a dot ("injection.") [title]
findings/F-001-sqli/finding.md warning impact: Impact is short [section:Impact]
yars: 1 errors, 1 warnings in 1 findings
`
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
	// the exit code: 1 with errors, 0 with --warn-only
	code, err := inDir(t, dir, func() (int, error) { return cmdLint([]string{"--staged"}, &out) })
	if err != nil || code != 1 {
		t.Fatalf("exit %d %v", code, err)
	}
	out.Reset()
	code, err = inDir(t, dir, func() (int, error) { return cmdLint([]string{"--staged", "--warn-only"}, &out) })
	if err != nil || code != 0 || !strings.HasSuffix(out.String(), "yars: 1 errors, 1 warnings in 1 findings (commit not blocked)\n") {
		t.Fatalf("--warn-only: exit %d %v\n%s", code, err, out.String())
	}
	// --data names the clone too
	out.Reset()
	if code, err := cmdLint([]string{"--staged", "--warn-only", "--data", dir}, &out); err != nil || code != 0 || !strings.Contains(out.String(), "title-dot") {
		t.Fatalf("--data: exit %d %v\n%s", code, err, out.String())
	}
}

// inDir runs fn with the working directory set to dir.
func inDir(t *testing.T, dir string, fn func() (int, error)) (int, error) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	return fn()
}

// A rule that could not run (a broken script, no AI provider) is shown as
// such and counts as neither error nor warning, as on push and the website.
func TestLintStagedCouldNotRun(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[{"rule":"acronyms-expanded","level":"warning","message":"AI rules skipped: no AI provider configured","target":"ai","quote":""},{"rule":"broken","level":"error","message":"the script crashed","target":"rules","quote":""}]}`)
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "pw")+"/git/e/acme")
	var out bytes.Buffer
	code, err := cmdLint([]string{"--staged", "--data", dir}, &out)
	want := "findings/F-001-sqli/finding.md could not run acronyms-expanded: AI rules skipped: no AI provider configured [ai]\n" +
		"findings/F-001-sqli/finding.md could not run broken: the script crashed [rules]\n" +
		"yars: 0 errors, 0 warnings in 1 findings\n"
	if err != nil || code != 0 || out.String() != want {
		t.Fatalf("exit %d %v:\n%s", code, err, out.String())
	}
}

func TestLintStagedSendsBasicAuth(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "s3cret:pw")+"/git/e/acme")
	var out bytes.Buffer
	if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
		t.Fatal(err)
	}
	if a := ls.logins(); len(a) != 1 || a[0] != "alice:s3cret:pw" {
		t.Fatalf("auth %q", a)
	}
	if strings.Contains(out.String(), "s3cret") {
		t.Fatalf("the password is printed:\n%s", out.String())
	}
}

// Review focus 2: a server that is down never blocks a commit: with
// --warn-only, as the hook runs it, the exit code is 0. Without it the code
// is 3, "not checked": neither clean (0) nor errors found (1).
func TestLintStagedServerDown(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	origin := withLogin(t, ls.URL, "alice", "pw") + "/git/e/acme"
	ls.Close()
	dir := lintClone(t, origin)
	host := strings.TrimPrefix(ls.URL, "http://")
	for args, want := range map[string]int{"": notChecked, "--warn-only": 0} {
		var out bytes.Buffer
		code, err := cmdLint(append(strings.Fields("--staged "+args), "--data", dir), &out)
		if err != nil || code != want || !strings.HasPrefix(out.String(), "yars: could not ask "+host+": ") || !strings.HasSuffix(out.String(), "; nothing checked\n") || strings.Count(out.String(), "\n") != 1 {
			t.Fatalf("%q: exit %d %v:\n%s", args, code, err, out.String())
		}
	}
}

// Every way of not asking the server is "not checked" (3) without
// --warn-only and 0 with it; a commit with no finding staged is clean (0).
func TestLintStagedNotCheckedExitCode(t *testing.T) {
	noUserGit(t)
	refused := newLintServer(t, 401, "authentication required\n")
	ok := newLintServer(t, 200, `{"violations":[]}`)
	failing := newLintServer(t, 500, "boom\n")
	for name, c := range map[string]struct{ origin, says string }{
		"not an engagement": {withLogin(t, ok.URL, "alice", "pw") + "/git/yars", "nothing checked"},
		"no saved login":    {ok.URL + "/git/e/acme", "no saved login"},
		"login refused":     {withLogin(t, refused.URL, "alice", "wrong") + "/git/e/acme", "login refused"},
		"server error":      {withLogin(t, failing.URL, "alice", "pw") + "/git/e/acme", "nothing checked"},
	} {
		dir := lintClone(t, c.origin)
		for args, want := range map[string]int{"": notChecked, "--warn-only": 0} {
			var out bytes.Buffer
			code, err := cmdLint(append(strings.Fields("--staged "+args), "--data", dir), &out)
			if err != nil || code != want || !strings.Contains(out.String(), c.says) {
				t.Errorf("%s %q: exit %d %v:\n%s", name, args, code, err, out.String())
			}
		}
	}
	// a clean answer is 0, and so is a commit that stages no finding
	dir := lintClone(t, withLogin(t, ok.URL, "alice", "pw")+"/git/e/acme")
	var out bytes.Buffer
	if code, err := cmdLint([]string{"--staged", "--data", dir}, &out); err != nil || code != 0 {
		t.Fatalf("clean: exit %d %v:\n%s", code, err, out.String())
	}
	gitT(t, dir, "commit", "-q", "-m", "first")
	out.Reset()
	if code, err := cmdLint([]string{"--staged", "--data", dir}, &out); err != nil || code != 0 || out.Len() != 0 {
		t.Fatalf("nothing staged: exit %d %v:\n%s", code, err, out.String())
	}
}

func TestLintStagedTimesOut(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	ls.sleep = 10 * time.Second
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "pw")+"/git/e/acme")
	old := lintTimeout
	lintTimeout = 200 * time.Millisecond
	defer func() { lintTimeout = old }()
	for args, want := range map[string]int{"": notChecked, "--warn-only": 0} {
		var out bytes.Buffer
		start := time.Now()
		code, err := cmdLint(append(strings.Fields("--staged "+args), "--data", dir), &out)
		if took := time.Since(start); took > 2*time.Second || err != nil || code != want || !strings.Contains(out.String(), "could not ask") || !strings.Contains(out.String(), "nothing checked") {
			t.Fatalf("%q: took %v, exit %d %v:\n%s", args, took, code, err, out.String())
		}
	}
}

func TestLintStagedRefusedLogin(t *testing.T) {
	ls := newLintServer(t, 401, "authentication required\n")
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "wrong")+"/git/e/acme")
	var out bytes.Buffer
	e, w, err := lintStaged(context.Background(), dir, &out, false)
	if err != nil || e != 0 || w != 0 || !strings.Contains(out.String(), "could not ask") || !strings.Contains(out.String(), "login refused") {
		t.Fatalf("%d %d %v:\n%s", e, w, err, out.String())
	}
}

// A stale saved password costs one failed login, not one per finding (the
// lockout counts git and website logins alike), and git forgets it, as git
// does after a 401: the next commit says there is no saved login.
func TestLintStagedRefusedLoginOnce(t *testing.T) {
	ls := newLintServer(t, 401, "authentication required\n")
	dir := lintClone(t, ls.URL+"/git/e/acme")
	noUserGit(t)
	for _, id := range []string{"F-002-a", "F-003-b", "F-004-c"} {
		write(t, filepath.Join(dir, "findings", id, "finding.md"), "---\nid: "+id[:5]+"\ntitle: x\n---\n")
	}
	gitT(t, dir, "add", "-A")
	cred := filepath.Join(t.TempDir(), "creds")
	u, _ := url.Parse(ls.URL)
	write(t, cred, "http://alice:old@"+u.Host+"\n")
	gitT(t, dir, "config", "credential.helper", "store --file="+cred)
	var out bytes.Buffer
	if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
		t.Fatal(err)
	}
	ls.mu.Lock()
	probes := ls.probes
	ls.mu.Unlock()
	if !strings.Contains(out.String(), "login refused") || len(ls.requests()) != 0 || probes != 1 {
		t.Fatalf("%d posts, %d login checks:\n%s", len(ls.requests()), probes, out.String())
	}
	if b, _ := os.ReadFile(cred); strings.Contains(string(b), "alice:old") {
		t.Fatalf("the refused login is still saved: %q", b)
	}
	out.Reset()
	if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
		t.Fatal(err)
	}
	ls.mu.Lock()
	probes = ls.probes
	ls.mu.Unlock()
	if !strings.Contains(out.String(), "no saved login") || len(ls.requests()) != 0 || probes != 1 {
		t.Fatalf("again: %d posts, %d login checks:\n%s", len(ls.requests()), probes, out.String())
	}
}

func TestLintStagedNotAnEngagementClone(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "pw")+"/git/yars")
	var out bytes.Buffer
	if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
		t.Fatal(err)
	}
	if out.String() != "yars: this clone's origin is not a YARS engagement (/git/e/<id>); nothing checked\n" || len(ls.requests()) != 0 {
		t.Fatalf("%q %q", out.String(), ls.requests())
	}
}

func TestLintStagedUnparseable(t *testing.T) {
	ls := newLintServer(t, 422, `{"error":"yaml: line 1: did not find expected node content"}`)
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "pw")+"/git/e/acme")
	var out bytes.Buffer
	e, _, err := lintStaged(context.Background(), dir, &out, false)
	if err != nil || e != 1 || !strings.Contains(out.String(), "findings/F-001-sqli/finding.md error parse: yaml: line 1: did not find expected node content\n") {
		t.Fatalf("%d %v:\n%s", e, err, out.String())
	}
}

// Review focus 2: a credential helper that waits (a keyring dialog nobody
// answers) does not hold the commit past the time limit.
func TestLintStagedSlowHelper(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	dir := lintClone(t, ls.URL+"/git/e/acme")
	noUserGit(t)
	helper := filepath.Join(t.TempDir(), "slow-helper")
	write(t, helper, "#!/bin/sh\nsleep 30\n")
	os.Chmod(helper, 0o755)
	gitT(t, dir, "config", "credential.helper", helper)
	old := lintTimeout
	lintTimeout = 200 * time.Millisecond
	defer func() { lintTimeout = old }()
	host := strings.TrimPrefix(ls.URL, "http://")
	for args, want := range map[string]int{"": notChecked, "--warn-only": 0} {
		var out bytes.Buffer
		start := time.Now()
		code, err := cmdLint(append(strings.Fields("--staged "+args), "--data", dir), &out)
		if took := time.Since(start); took > 3*time.Second || err != nil || code != want ||
			out.String() != "yars: could not ask "+host+": no answer within 200ms; nothing checked\n" || len(ls.requests()) != 0 {
			t.Fatalf("%q: took %v, exit %d %v:\n%s", args, took, code, err, out.String())
		}
	}
}

// A finding whose folder moved in the commit is checked as the new file
// (rename detection would hide it from the list).
func TestLintStagedRenamedFinding(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "pw")+"/git/e/acme")
	gitT(t, dir, "commit", "-q", "-m", "first")
	gitT(t, dir, "mv", "findings/F-001-sqli", "findings/F-001-sql-injection")
	write(t, filepath.Join(dir, "findings", "F-001-sql-injection", "finding.md"), "---\nid: F-001\ntitle: SQL injection.\n---\n## Description\nstaged\n")
	gitT(t, dir, "add", "-A")
	var out bytes.Buffer
	if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
		t.Fatal(err)
	}
	if reqs := ls.requests(); len(reqs) != 1 || !strings.Contains(reqs[0], "title: SQL injection.") {
		t.Fatalf("requests %q", reqs)
	}
}

// Without a login in the URL, git's credential helper gives it; with none
// saved, the user is told what to do and nothing is posted.
func TestLintStagedNoSavedLogin(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	dir := lintClone(t, ls.URL+"/git/e/acme")
	noUserGit(t) // no user config, no stored credentials
	var out bytes.Buffer
	if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(ls.URL, "http://")
	if out.String() != "yars: no saved login for "+host+"; save one for git (a credential helper, then git fetch once; or a Git token in the clone URL) and commit again\n" || len(ls.requests()) != 0 {
		t.Fatalf("%q %q", out.String(), ls.requests())
	}
	// a store helper with the login: it is used
	cred := filepath.Join(t.TempDir(), "creds")
	u, _ := url.Parse(ls.URL)
	write(t, cred, "http://bob:pw2@"+u.Host+"\n")
	gitT(t, dir, "config", "credential.helper", "store --file="+cred)
	out.Reset()
	if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
		t.Fatal(err)
	}
	if a := ls.logins(); len(a) != 1 || a[0] != "bob:pw2" {
		t.Fatalf("auth %q, output %q", a, out.String())
	}
}

// The login is never asked for: an askpass program set in git's config is
// not run (a window nobody answers would hold the commit).
func TestLintStagedNeverPrompts(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	dir := lintClone(t, ls.URL+"/git/e/acme")
	noUserGit(t)
	marker := filepath.Join(t.TempDir(), "asked")
	askpass := filepath.Join(t.TempDir(), "askpass")
	write(t, askpass, "#!/bin/sh\ntouch "+marker+"\necho pw\n")
	os.Chmod(askpass, 0o755)
	gitT(t, dir, "config", "core.askPass", askpass)
	t.Setenv("SSH_ASKPASS", askpass)
	var out bytes.Buffer
	if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil || !strings.Contains(out.String(), "no saved login") || len(ls.requests()) != 0 {
		t.Fatalf("asked: %v; output %q", err == nil, out.String())
	}
}

// Several findings are asked about at the same time, so slow AI rules on
// two of them do not use up the run's time.
func TestLintStagedAsksInParallel(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	ls.sleep = 400 * time.Millisecond
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "pw")+"/git/e/acme")
	for _, id := range []string{"F-002-a", "F-003-b", "F-004-c"} {
		write(t, filepath.Join(dir, "findings", id, "finding.md"), "---\nid: "+id[:5]+"\ntitle: x\n---\n")
	}
	gitT(t, dir, "add", "-A")
	old := lintTimeout
	lintTimeout = 700 * time.Millisecond // one round fits, two do not
	defer func() { lintTimeout = old }()
	var out bytes.Buffer
	if code, err := cmdLint([]string{"--staged", "--data", dir}, &out); err != nil || code != 0 || !strings.HasSuffix(out.String(), "yars: 0 errors, 0 warnings in 4 findings\n") {
		t.Fatalf("exit %d %v:\n%s", code, err, out.String())
	}
}

// git's own TLS settings for the server apply: a private CA (http.sslCAInfo)
// or http.sslVerify=false; without them a self-signed server is refused.
func TestLintStagedUsesGitTLSSettings(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		io.WriteString(w, `{"violations":[]}`)
	}))
	defer srv.Close()
	noUserGit(t)
	dir := lintClone(t, withLogin(t, srv.URL, "alice", "pw")+"/git/e/acme")
	run := func() string {
		var out bytes.Buffer
		if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	if got := run(); !strings.Contains(got, "could not ask") || !strings.Contains(got, "certificate") {
		t.Fatalf("an unknown CA: %q", got)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	write(t, ca, string(pemOf(srv.Certificate().Raw)))
	gitT(t, dir, "config", "http.sslCAInfo", ca)
	if got := run(); !strings.Contains(got, "in 1 findings") {
		t.Fatalf("http.sslCAInfo: %q", got)
	}
	gitT(t, dir, "config", "--unset", "http.sslCAInfo")
	gitT(t, dir, "config", "http.sslVerify", "false")
	if got := run(); !strings.Contains(got, "in 1 findings") {
		t.Fatalf("http.sslVerify=false: %q", got)
	}
}

func pemOf(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
