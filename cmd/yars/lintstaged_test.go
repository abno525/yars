package main

import (
	"bytes"
	"context"
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
	bodies []string
	auths  []string
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
		ls.bodies = append(ls.bodies, r.Method+" "+r.URL.Path+"\n"+string(b))
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

func TestLintStagedSendsBasicAuth(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "s3cret:pw")+"/git/e/acme")
	var out bytes.Buffer
	if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
		t.Fatal(err)
	}
	if ls.auths[0] != "alice:s3cret:pw" {
		t.Fatalf("auth %q", ls.auths)
	}
	if strings.Contains(out.String(), "s3cret") {
		t.Fatalf("the password is printed:\n%s", out.String())
	}
}

// Review focus 2: a server that is down never blocks a commit.
func TestLintStagedServerDown(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	origin := withLogin(t, ls.URL, "alice", "pw") + "/git/e/acme"
	ls.Close()
	dir := lintClone(t, origin)
	var out bytes.Buffer
	code, err := cmdLint([]string{"--staged", "--data", dir}, &out)
	host := strings.TrimPrefix(ls.URL, "http://")
	if err != nil || code != 0 || !strings.HasPrefix(out.String(), "yars: could not ask "+host+": ") || !strings.HasSuffix(out.String(), "; nothing checked\n") || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("exit %d %v:\n%s", code, err, out.String())
	}
}

func TestLintStagedTimesOut(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	ls.sleep = 10 * time.Second
	dir := lintClone(t, withLogin(t, ls.URL, "alice", "pw")+"/git/e/acme")
	old := lintTimeout
	lintTimeout = 200 * time.Millisecond
	defer func() { lintTimeout = old }()
	var out bytes.Buffer
	start := time.Now()
	code, err := cmdLint([]string{"--staged", "--data", dir}, &out)
	if took := time.Since(start); took > 2*time.Second || err != nil || code != 0 || !strings.Contains(out.String(), "could not ask") || !strings.Contains(out.String(), "nothing checked") {
		t.Fatalf("took %v, exit %d %v:\n%s", took, code, err, out.String())
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

// Without a login in the URL, git's credential helper gives it; with none
// saved, the user is told what to do and nothing is posted.
func TestLintStagedNoSavedLogin(t *testing.T) {
	ls := newLintServer(t, 200, `{"violations":[]}`)
	dir := lintClone(t, ls.URL+"/git/e/acme")
	t.Setenv("HOME", t.TempDir()) // no user config, no stored credentials
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	var out bytes.Buffer
	if _, _, err := lintStaged(context.Background(), dir, &out, false); err != nil {
		t.Fatal(err)
	}
	host := strings.TrimPrefix(ls.URL, "http://")
	if out.String() != "yars: no saved login for "+host+"; run git fetch once, then commit again\n" || len(ls.requests()) != 0 {
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
	if len(ls.auths) != 1 || ls.auths[0] != "bob:pw2" {
		t.Fatalf("auth %q, output %q", ls.auths, out.String())
	}
}
