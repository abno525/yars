package gitserve

import (
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/db"
)

func statusBody(t *testing.T, url, user, pw string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(user, pw)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// R5: an account with an unchanged temporary password is told what to do,
// over a token and over the temporary password alike, not just refused.
func TestMustChangeSaysSetANewPassword(t *testing.T) {
	srv, _, d := setupDB(t)
	tk := auth.NewTokens(d)
	tok, _, err := tk.Create("alice", "alice", db.TokenSpec{Kind: db.TokenGit, Scopes: []string{db.ScopeAll}})
	if err != nil {
		t.Fatal(err)
	}
	temp, _ := auth.HashPassword("temporary-pw-1")
	if err := d.ResetPassword("alice", temp); err != nil {
		t.Fatal(err)
	}
	fetch := srv.URL + "/git/e/acme/info/refs?service=git-upload-pack"
	const want = "set a new password first (log in on the website)"
	for name, pw := range map[string]string{"token": tok, "temporary password": "temporary-pw-1"} {
		c, body := statusBody(t, fetch, "alice", pw)
		if c != 403 || !strings.Contains(body, want) {
			t.Errorf("%s: %d %q", name, c, body)
		}
	}
	// a wrong password stays the plain refusal
	if c, body := statusBody(t, fetch, "alice", "wrong-pw-1"); c != 401 || strings.Contains(body, want) {
		t.Errorf("wrong password: %d %q", c, body)
	}
	// git itself shows the message
	url := strings.Replace(srv.URL, "http://", "http://alice:"+tok+"@", 1) + "/git/e/acme"
	cmd := exec.Command("git", "clone", "-q", url, filepath.Join(t.TempDir(), "c"))
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), want) {
		t.Errorf("clone: %v %s", err, out)
	}
}
