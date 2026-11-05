package gitserve

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/auth"
	"yars/internal/db"
)

func status(t *testing.T, method, url, user, pw string) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	req.SetBasicAuth(user, pw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Engagement repos are for the engagement's team (and directors, admins).
func TestNonMemberForbidden(t *testing.T) {
	srv, _, d := setupDB(t)
	refs := srv.URL + "/git/e/acme/info/refs?service=git-upload-pack"
	if c := status(t, "GET", refs, "pen2", "pw"); c != 403 {
		t.Fatalf("non-member: %d", c)
	}
	if c := status(t, "GET", refs, "alice", "pw"); c != 200 {
		t.Fatalf("member: %d", c)
	}
	// the main repo (settings) is open to every account
	if c := status(t, "GET", srv.URL+"/git/yars/info/refs?service=git-upload-pack", "pen2", "pw"); c != 200 {
		t.Fatalf("main repo: %d", c)
	}
	d.SetDisabled("alice", true)
	if c := status(t, "GET", refs, "alice", "pw"); c != 401 {
		t.Fatalf("disabled account: %d", c)
	}
}

func TestGitTokens(t *testing.T) {
	srv, _, d := setupDB(t)
	tk := auth.NewTokens(d)
	read, _, err := tk.Create("alice", "alice", db.TokenSpec{Kind: db.TokenGit, Scopes: []string{db.ScopeRead}})
	if err != nil {
		t.Fatal(err)
	}
	edit, _, _ := tk.Create("alice", "alice", db.TokenSpec{Kind: db.TokenGit, Scopes: []string{"edit"}, Engagements: []string{"acme"}})
	mcpTok, _, _ := tk.Create("alice", "alice", db.TokenSpec{Kind: db.TokenMCP, Scopes: []string{db.ScopeAll}})
	fetch := srv.URL + "/git/e/acme/info/refs?service=git-upload-pack"
	push := srv.URL + "/git/e/acme/info/refs?service=git-receive-pack"
	if c := status(t, "GET", fetch, "alice", read); c != 200 {
		t.Fatalf("read token fetch: %d", c)
	}
	if c := status(t, "GET", push, "alice", read); c != 403 {
		t.Fatalf("read token push: %d", c)
	}
	if c := status(t, "POST", srv.URL+"/git/e/acme/git-receive-pack", "alice", read); c != 403 {
		t.Fatalf("read token receive-pack: %d", c)
	}
	if c := status(t, "GET", push, "alice", edit); c != 200 {
		t.Fatalf("edit token push: %d", c)
	}
	// a token of another account, or of the MCP kind, is not a password
	if c := status(t, "GET", fetch, "pen2", read); c != 401 {
		t.Fatalf("token under another name: %d", c)
	}
	if c := status(t, "GET", fetch, "alice", mcpTok); c != 401 {
		t.Fatalf("mcp token on git: %d", c)
	}
	// a token limited to engagements can't reach the main repo
	if c := status(t, "GET", srv.URL+"/git/yars/info/refs?service=git-upload-pack", "alice", edit); c != 403 {
		t.Fatalf("restricted token on the main repo: %d", c)
	}
	// a real clone with a read token works; its push is refused
	dst := filepath.Join(t.TempDir(), "clone")
	url := strings.Replace(srv.URL, "http://", "http://alice:"+read+"@", 1) + "/git/e/acme"
	cmd := exec.Command("git", "clone", "-q", url, dst)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	os.WriteFile(filepath.Join(dst, "notes.txt"), []byte("hi\n"), 0o644)
	gitCmd(t, dst, "add", "-A")
	gitCmd(t, dst, "commit", "-qm", "note")
	p := exec.Command("git", "-C", dst, "push", "-q", "origin", "HEAD")
	p.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := p.CombinedOutput(); err == nil {
		t.Fatalf("read token pushed: %s", out)
	}
}
