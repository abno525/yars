package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/gitserve"
	"yars/internal/rules"
	"yars/internal/store"
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
		want := "#!/bin/sh\n" + hookMarker + "\ntest -x '/opt/yars bin/yars' || exit 0\nexec '/opt/yars bin/yars' lint --staged --warn-only\n"
		if string(b) != want {
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
	if strings.Contains(string(b), "/old/yars") || strings.Count(string(b), "/new/yars") != 2 || strings.Count(string(b), hookMarker) != 1 {
		t.Fatalf("hook:\n%s", b)
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
