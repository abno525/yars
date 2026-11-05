package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/gitserve"
	"yars/internal/store"
)

type pushEnv struct {
	t     *testing.T
	repo  *gitrepo.Repo // the server's acme engagement repo
	st    *store.Store
	clone string // recursive clone of the main repo
	url   string
}

// Each engagement can be cloned on its own; its history holds only that
// engagement's commits.
func TestEngagementCloneHistory(t *testing.T) {
	p := newPushEnv(t)
	dst := filepath.Join(t.TempDir(), "acme")
	cmd := exec.Command("git", "clone", "-q", strings.Replace(p.url, "http://", "http://alice:pw@", 1)+"/git/e/acme", dst)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	log, _ := exec.Command("git", "-C", dst, "log", "--format=%s").Output()
	if string(log) != "F-001: create\nengagement acme: create\n" {
		t.Fatalf("history:\n%s", log)
	}
	if _, err := os.Stat(filepath.Join(dst, "findings", "F-001-sqli", "finding.md")); err != nil {
		t.Fatal("finding missing from the engagement clone")
	}
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
	d := openDB(t, dir)
	for _, u := range users {
		d.AddUser(u) // the database stays on the server
	}
	st := store.New(r, config.Default(), d)
	alice := users[0]
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, users[1].GitAuthor())
	st.CreateFinding("acme", "SQLi", alice.GitAuthor())

	gs := &gitserve.Server{Repo: r, Auth: auth.New(d), HookCmd: hookCmd(bin, dir), Sync: st.SyncPointers, Invalidate: st.Invalidate}
	if err := gs.Setup(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/git/", gs.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// download everything: the main repo with every engagement as a submodule
	clone := filepath.Join(t.TempDir(), "clone")
	url := strings.Replace(srv.URL, "http://", "http://alice:pw@", 1) + "/git/yars"
	cmd := exec.Command("git", "clone", "-q", "--recurse-submodules", url, clone)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	er, _ := st.EngRepo("acme")
	p := &pushEnv{t: t, repo: er, st: st, clone: clone, url: srv.URL}
	if out, err := p.git("switch", "-q", "main"); err != nil {
		t.Fatalf("switch: %v %s", err, out)
	}
	return p
}

// git runs in the acme engagement inside the recursive clone.
func (p *pushEnv) git(args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", filepath.Join(p.clone, "engagements", "acme"), "-c", "user.name=alice", "-c", "user.email=a@a", "-c", "commit.gpgsign=false"}, args...)...)
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
	if err == nil || !strings.Contains(out, "remote: yars:") || !strings.Contains(out, "managed in YARS") {
		t.Fatalf("forbidden push: err=%v\n%s", err, out)
	}
	if after, _ := p.repo.Head(); after != before {
		t.Fatal("server HEAD moved after a rejected push")
	}
}

// The hook reads workflow state from the database: once a finding is
// approved, a pentester's push to it is refused.
func TestPushLockedByDatabaseState(t *testing.T) {
	p := newPushEnv(t)
	d := p.st.DB()
	if err := d.Tx(func(tx *db.Tx) error {
		return tx.PutState("acme", "F-001", db.State{Status: "complete"})
	}); err != nil {
		t.Fatal(err)
	}
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "late") })
	if out, err := p.git("push", "origin", "HEAD"); err == nil || !strings.Contains(out, "complete") {
		t.Fatalf("locked finding pushed: err=%v\n%s", err, out)
	}
}

// An AI editing the local clone through MCP stdio commits as the user; the
// push of that commit passes the server policy.
func TestMCPStdioThenPush(t *testing.T) {
	p := newPushEnv(t)
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"update_section","arguments":{"engagement":"acme","finding":"F-001","section":"Impact","body":"Written by the assistant."}}}` + "\n")
	var out bytes.Buffer
	if err := runMCP([]string{"--data", p.clone, "--user", "alice"}, in, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "isError") {
		t.Fatalf("mcp error: %s", out.String())
	}
	if o, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("push rejected: %v\n%s", err, o)
	}
	ref, _ := p.st.Finding("acme", "F-001-sqli")
	if b, _ := ref.F.Section("Impact"); !strings.Contains(b, "Written by the assistant.") {
		t.Fatalf("server not updated: %q", b)
	}
}

func TestTokensUntracked(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	openDB(t, dir).AddUser(config.User{Username: "alice", Role: "pentester"})
	var out bytes.Buffer
	if code, _ := cmdToken([]string{"add", "--data", dir, "mallory"}, &out); code == 0 {
		t.Fatal("token for unknown user")
	}
	if code, err := cmdToken([]string{"add", "--data", dir, "alice"}, &out); code != 0 || err != nil || !strings.Contains(out.String(), "yars_") {
		t.Fatalf("token add: %d %v %s", code, err, out.String())
	}
	r, _ := gitrepo.Open(dir)
	if r.Tracked(".yars/tokens.yaml") {
		t.Fatal("tokens tracked")
	}
	st, _ := exec.Command("git", "-C", dir, "status", "--porcelain").Output()
	if len(st) != 0 {
		t.Fatalf("tokens file not ignored: %s", st)
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
