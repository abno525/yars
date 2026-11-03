package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/gitserve"
	"yars/internal/store"
)

type pushEnv struct {
	t     *testing.T
	repo  *gitrepo.Repo
	st    *store.Store
	clone string
}

func newPushEnv(t *testing.T) *pushEnv {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "yars")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	dir := filepath.Join(t.TempDir(), "data")
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	r, _ := gitrepo.Open(dir)
	hash, _ := auth.HashPassword("pw")
	users := []config.User{{Username: "alice", Role: "pentester", PasswordHash: hash}, {Username: "dora", Role: "director", PasswordHash: hash}}
	config.SaveUsers(dir, users)
	r.Commit([]string{".yars/users.yaml"}, "users", system)
	st := store.New(r, config.Default())
	alice := users[0]
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, users[1].GitAuthor())
	st.CreateFinding("acme", "SQLi", alice.GitAuthor())

	gs := &gitserve.Server{Repo: r, Auth: auth.New(users), HookCmd: hookCmd(bin, dir)}
	if err := gs.Setup(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/git/", gs.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	clone := filepath.Join(t.TempDir(), "clone")
	url := strings.Replace(srv.URL, "http://", "http://alice:pw@", 1) + "/git/yars"
	if out, err := exec.Command("git", "clone", "-q", url, clone).CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	return &pushEnv{t: t, repo: r, st: st, clone: clone}
}

func (p *pushEnv) git(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", p.clone, "-c", "user.name=alice", "-c", "user.email=a@a", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (p *pushEnv) editFinding(fn func(f *finding.Finding)) {
	path := filepath.Join(p.clone, "engagements", "acme", "findings", "F-001-sqli", "finding.md")
	b, _ := os.ReadFile(path)
	f, err := finding.Parse(b)
	if err != nil {
		p.t.Fatal(err)
	}
	fn(f)
	os.WriteFile(path, f.Bytes(), 0o644)
	if out, err := p.git("commit", "-qam", "edit"); err != nil {
		p.t.Fatalf("commit: %v %s", err, out)
	}
}

func TestPushEndToEnd(t *testing.T) {
	p := newPushEnv(t)
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "Full database read.") })
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("allowed push rejected: %v\n%s", err, out)
	}
	ref, err := p.st.Finding("acme", "F-001-sqli")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := ref.F.Section("Impact"); !strings.Contains(b, "Full database read.") {
		t.Fatalf("server not updated: %q", b)
	}

	before, _ := p.repo.Head()
	p.editFinding(func(f *finding.Finding) { f.SetMeta("status", "complete") })
	out, err := p.git("push", "origin", "HEAD")
	if err == nil || !strings.Contains(out, "remote: yars:") || !strings.Contains(out, "draft → complete") {
		t.Fatalf("forbidden push: err=%v\n%s", err, out)
	}
	if after, _ := p.repo.Head(); after != before {
		t.Fatal("server HEAD moved after a rejected push")
	}
}

func TestPushForceRejected(t *testing.T) {
	p := newPushEnv(t)
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "one") })
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	p.git("reset", "-q", "--hard", "HEAD~1")
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "rewritten") })
	if out, err := p.git("push", "--force", "origin", "HEAD"); err == nil {
		t.Fatalf("force push accepted:\n%s", out)
	}
}
