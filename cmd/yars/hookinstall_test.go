package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/gitserve"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/store"
)

// useHookBin makes cmdHookInstall write bin into the hooks.
func useHookBin(t *testing.T, bin string) {
	t.Helper()
	old := hookBin
	hookBin = func() (string, error) { return bin, nil }
	t.Cleanup(func() { hookBin = old })
}

// mainClone is a folder laid out as a main clone with engagement
// repositories a and b (and c, not checked out).
func mainClone(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write(t, filepath.Join(dir, ".yars", "config.yaml"), "{}\n")
	for _, id := range []string{"a", "b"} {
		e := filepath.Join(dir, "engagements", id)
		if err := os.MkdirAll(e, 0o755); err != nil {
			t.Fatal(err)
		}
		gitT(t, e, "init", "-q")
	}
	os.MkdirAll(filepath.Join(dir, "engagements", "c"), 0o755)
	return dir
}

func hookAt(t *testing.T, repo string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repo, "rev-parse", "--git-path", "hooks/pre-commit").Output()
	if err != nil {
		t.Fatal(err)
	}
	p := strings.TrimSpace(string(out))
	if !filepath.IsAbs(p) {
		p = filepath.Join(repo, p)
	}
	return p
}

func TestHookInstallWritesEveryEngagement(t *testing.T) {
	useHookBin(t, "/opt/yars bin/yars")
	dir := mainClone(t)
	var out bytes.Buffer
	if err := cmdHookInstall([]string{"--data", dir}, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "installed a\ninstalled b\n2 installed\n" {
		t.Fatalf("output:\n%s", out.String())
	}
	for _, id := range []string{"a", "b"} {
		p := hookAt(t, filepath.Join(dir, "engagements", id))
		st, err := os.Stat(p)
		if err != nil || st.Mode().Perm()&0o111 == 0 {
			t.Fatalf("%s: %v %v", id, st, err)
		}
		b, _ := os.ReadFile(p)
		if string(b) != hookBody("/opt/yars bin/yars") {
			t.Fatalf("%s hook:\n%s", id, b)
		}
	}
	// the current folder is the default
	out.Reset()
	if _, err := inDir(t, dir, func() (int, error) { return 0, cmdHookInstall(nil, &out) }); err != nil || !strings.HasSuffix(out.String(), "2 installed\n") {
		t.Fatalf("default folder: %v\n%s", err, out.String())
	}
}

// An engagement clone of its own is its one target.
func TestHookInstallEngagementClone(t *testing.T) {
	useHookBin(t, "/usr/bin/yars")
	dir := lintClone(t, "http://h/git/e/acme")
	var out bytes.Buffer
	if err := cmdHookInstall([]string{"--data", dir}, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "installed acme\n1 installed\n" {
		t.Fatalf("output:\n%s", out.String())
	}
	if b, _ := os.ReadFile(hookAt(t, dir)); !strings.Contains(string(b), hookMarker) {
		t.Fatalf("hook:\n%s", b)
	}
}

// Review focus 5: a hook the user wrote is left as it is.
func TestHookInstallKeepsForeignHook(t *testing.T) {
	useHookBin(t, "/usr/bin/yars")
	dir := mainClone(t)
	p := hookAt(t, filepath.Join(dir, "engagements", "a"))
	write(t, p, "#!/bin/sh\necho mine\n")
	var out bytes.Buffer
	if err := cmdHookInstall([]string{"--data", dir}, &out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "#!/bin/sh\necho mine\n" {
		t.Fatalf("the user's hook changed:\n%s", b)
	}
	want := p + ": a pre-commit hook exists already; add this line to it: '/usr/bin/yars' lint --staged --warn-only\ninstalled b\n1 installed\n"
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
}

// With core.hooksPath set (a tracked folder in the work tree, or one
// shared by every repository), nothing is written there: the output names
// the setting and the line to add.
func TestHookInstallLeavesHooksPath(t *testing.T) {
	useHookBin(t, "/usr/bin/yars")
	dir := mainClone(t)
	a := filepath.Join(dir, "engagements", "a")
	gitT(t, a, "config", "core.hooksPath", ".githooks")
	var out bytes.Buffer
	if err := cmdHookInstall([]string{"--data", dir}, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(a, ".githooks")); err == nil {
		t.Fatal("a hook was written into the work tree")
	}
	want := a + ": core.hooksPath is set (.githooks); add this line to its pre-commit hook: '/usr/bin/yars' lint --staged --warn-only\ninstalled b\n1 installed\n"
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestHookInstallReplacesOwnHook(t *testing.T) {
	dir := mainClone(t)
	useHookBin(t, "/old/yars")
	var out bytes.Buffer
	if err := cmdHookInstall([]string{"--data", dir}, &out); err != nil {
		t.Fatal(err)
	}
	useHookBin(t, "/new/yars")
	out.Reset()
	if err := cmdHookInstall([]string{"--data", dir}, &out); err != nil || !strings.HasSuffix(out.String(), "2 installed\n") {
		t.Fatalf("%v\n%s", err, out.String())
	}
	b, _ := os.ReadFile(hookAt(t, filepath.Join(dir, "engagements", "a")))
	if string(b) != hookBody("/new/yars") {
		t.Fatalf("hook:\n%s", b)
	}
}

// The hook's text: it never stops a commit, and says so when the binary it
// names is gone (an upgrade moved it).
func TestHookBody(t *testing.T) {
	want := "#!/bin/sh\n" + hookMarker + "\n" +
		"if ! test -x '/opt/y'\\''s/yars'; then\n" +
		"  echo \"yars: '/opt/y'\\''s/yars' not found; this commit was not checked; run yars hook install again\" >&2\n" +
		"  exit 0\nfi\n" +
		"'/opt/y'\\''s/yars' lint --staged --warn-only\nexit 0\n"
	if got := hookBody("/opt/y's/yars"); got != want {
		t.Fatalf("hook:\n%s\nwant:\n%s", got, want)
	}
	if !ownHook([]byte(hookBody("/a b/yars"))) || ownHook([]byte(hookBody("/a/yars")+"echo extra\n")) || ownHook([]byte("#!/bin/sh\n"+hookMarker+"\n")) {
		t.Fatal("ownHook")
	}
}

// commitIn commits everything in repo; the output and whether git refused.
func commitIn(t *testing.T, repo, msg string) (string, error) {
	t.Helper()
	gitT(t, repo, "add", "-A")
	cmd := exec.Command("git", "-C", repo, "-c", "user.name=alice", "-c", "user.email=a@a", "-c", "commit.gpgsign=false", "commit", "-q", "-m", msg)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// A binary that is gone, or that fails, never blocks a commit.
func TestHookNeverBlocksWhenTheBinaryFails(t *testing.T) {
	dir := lintClone(t, "http://h/git/e/acme")
	useHookBin(t, filepath.Join(t.TempDir(), "gone", "yars"))
	var out bytes.Buffer
	if err := cmdHookInstall([]string{"--data", dir}, &out); err != nil {
		t.Fatal(err)
	}
	got, err := commitIn(t, dir, "one")
	if err != nil || !strings.Contains(got, "not found; this commit was not checked; run yars hook install again") {
		t.Fatalf("gone: %v\n%s", err, got)
	}
	crash := filepath.Join(t.TempDir(), "yars")
	write(t, crash, "#!/bin/sh\necho panic >&2\nexit 2\n")
	os.Chmod(crash, 0o755)
	useHookBin(t, crash)
	if err := cmdHookInstall([]string{"--data", dir}, &out); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "notes.txt"), "x")
	if got, err := commitIn(t, dir, "two"); err != nil || !strings.Contains(got, "panic") {
		t.Fatalf("a failing binary blocked the commit: %v\n%s", err, got)
	}
}

// The hook names the binary as PATH finds it when that is the same file
// (a Homebrew or Nix link survives an upgrade; the resolved path does not).
func TestHookInstallUsesPathName(t *testing.T) {
	cellar := filepath.Join(t.TempDir(), "Cellar", "yars", "1.2")
	write(t, filepath.Join(cellar, "yars"), "#!/bin/sh\n")
	os.Chmod(filepath.Join(cellar, "yars"), 0o755)
	bin := t.TempDir()
	if err := os.Symlink(filepath.Join(cellar, "yars"), filepath.Join(bin, "yars")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	useHookBin(t, filepath.Join(cellar, "yars"))
	dir := lintClone(t, "http://h/git/e/acme")
	var out bytes.Buffer
	if err := cmdHookInstall([]string{"--data", dir}, &out); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(hookAt(t, dir)); string(b) != hookBody(filepath.Join(bin, "yars")) {
		t.Fatalf("hook:\n%s", b)
	}
}

// One engagement that cannot take the hook does not stop the others; the
// run ends with an error. A symlink, a folder or our hook with lines added
// counts as a hook someone else wrote.
func TestHookInstallGoesOn(t *testing.T) {
	useHookBin(t, "/usr/bin/yars")
	dir := mainClone(t)
	for _, id := range []string{"c", "d", "e"} {
		gitT(t, filepath.Join(dir, "engagements"), "init", "-q", id)
	}
	// a: a .git file pointing at a modules folder that was removed
	os.RemoveAll(filepath.Join(dir, "engagements", "a", ".git"))
	write(t, filepath.Join(dir, "engagements", "a", ".git"), "gitdir: /nonexistent/modules/a\n")
	// c: a dangling symlink, d: a folder, e: our hook with a line added
	pc := hookAt(t, filepath.Join(dir, "engagements", "c"))
	os.MkdirAll(filepath.Dir(pc), 0o755)
	os.Symlink("/nonexistent/hook", pc)
	pd := hookAt(t, filepath.Join(dir, "engagements", "d"))
	os.MkdirAll(pd, 0o755)
	pe := hookAt(t, filepath.Join(dir, "engagements", "e"))
	write(t, pe, hookBody("/usr/bin/yars")+"echo mine\n")
	var out bytes.Buffer
	err := cmdHookInstall([]string{"--data", dir}, &out)
	got := out.String()
	if err == nil || !strings.Contains(got, filepath.Join(dir, "engagements", "a")+": ") || !strings.Contains(got, "installed b\n") || !strings.HasSuffix(got, "1 installed\n") {
		t.Fatalf("%v\n%s", err, got)
	}
	for _, p := range []string{pc, pd, pe} {
		if !strings.Contains(got, p+": a pre-commit hook exists already") {
			t.Errorf("%s not reported as someone else's:\n%s", p, got)
		}
	}
	if l, err := os.Readlink(pc); err != nil || l != "/nonexistent/hook" {
		t.Errorf("the symlink changed: %q %v", l, err)
	}
	if b, _ := os.ReadFile(pe); !strings.HasSuffix(string(b), "echo mine\n") {
		t.Errorf("the edited hook changed:\n%s", b)
	}
}

func TestHookInstallRefusesArguments(t *testing.T) {
	var out bytes.Buffer
	if err := cmdHookInstall([]string{"some/clone"}, &out); err == nil || !strings.Contains(err.Error(), "--data") {
		t.Fatalf("%v", err)
	}
}

func TestHookInstallNotAClone(t *testing.T) {
	var out bytes.Buffer
	dir := t.TempDir()
	if err := cmdHookInstall([]string{"--data", dir}, &out); err == nil || err.Error() != dir+" is not a YARS clone" {
		t.Fatalf("%v", err)
	}
	// the server's own data folder is not a clone either: its commits are
	// the server's
	data := filepath.Join(t.TempDir(), "data")
	if err := cmdInit([]string{data}); err != nil {
		t.Fatal(err)
	}
	openDB(t, data)
	if err := cmdHookInstall([]string{"--data", data}, &out); err == nil || !strings.Contains(err.Error(), "the server's data folder") {
		t.Fatalf("data folder: %v", err)
	}
}

// newHookEnv is a push environment whose server answers the lint endpoint
// with the data folder's rules (title-no-trailing-dot among them), and whose
// clone has the hook installed (the yars binary built for the tests).
func newHookEnv(t *testing.T) *pushEnv {
	t.Helper()
	p := newPushEnvWith(t, func(gs *gitserve.Server) {
		st := store.New(gs.Repo, config.Default(), nil)
		st.Linter = rules.NewEngine(rules.DirFor(gs.Repo.Dir), config.Default())
		gs.Lint = st.LintContent
	})
	useHookBin(t, hookBinary(t))
	var out bytes.Buffer
	if err := cmdHookInstall([]string{"--data", p.clone}, &out); err != nil || out.String() != "installed acme\n1 installed\n" {
		t.Fatalf("install: %v\n%s", err, out.String())
	}
	return p
}

// The hook lands where git looks for it: in a recursive clone, under the
// main clone's .git/modules.
func TestHookInstallSubmodulePath(t *testing.T) {
	p := newHookEnv(t)
	acme := filepath.Join(p.clone, "engagements", "acme")
	want := filepath.Join(p.clone, ".git", "modules", "engagements", "acme", "hooks", "pre-commit")
	if got := hookAt(t, acme); got != want {
		t.Fatalf("git looks at %s, want %s", got, want)
	}
	if b, err := os.ReadFile(want); err != nil || !strings.Contains(string(b), hookMarker) {
		t.Fatalf("hook: %v\n%s", err, b)
	}
}

// End to end: a commit that breaks a rule goes in, and git shows what the
// server found.
func TestHookNeverBlocksCommit(t *testing.T) {
	p := newHookEnv(t)
	path := filepath.Join(p.clone, "engagements", "acme", "findings", "F-001-sqli", "finding.md")
	b, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), "title: SQLi\n", "title: SQLi.\n", 1)), 0o644)
	out, err := p.git("commit", "-qam", "a dot")
	if err != nil || !strings.Contains(out, "title-no-trailing-dot") || !strings.Contains(out, "commit not blocked") {
		t.Fatalf("commit: %v\n%s", err, out)
	}
	if log, _ := p.git("log", "-1", "--format=%s"); strings.TrimSpace(log) != "a dot" {
		t.Fatalf("not committed: %s", log)
	}
}

func TestHookCommitWorksWithServerDown(t *testing.T) {
	p := newHookEnv(t)
	p.srv.Close()
	path := filepath.Join(p.clone, "engagements", "acme", "findings", "F-001-sqli", "finding.md")
	b, _ := os.ReadFile(path)
	os.WriteFile(path, append(b, []byte("\nmore\n")...), 0o644)
	out, err := p.git("commit", "-qam", "offline")
	if err != nil || !strings.Contains(out, "could not ask") {
		t.Fatalf("commit: %v\n%s", err, out)
	}
	if log, _ := p.git("log", "-1", "--format=%s"); strings.TrimSpace(log) != "offline" {
		t.Fatalf("not committed: %s", log)
	}
}
