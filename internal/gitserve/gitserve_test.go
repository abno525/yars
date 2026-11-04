package gitserve

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

func setup(t *testing.T) (*httptest.Server, *gitrepo.Repo) {
	t.Helper()
	srv, r, _ := setupDB(t)
	return srv, r
}

func setupDB(t *testing.T) (*httptest.Server, *gitrepo.Repo, *db.DB) {
	t.Helper()
	r, err := gitrepo.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	st := store.New(r, config.Default(), d)
	if err := st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, gitrepo.Author{Name: "a", Email: "a@a"}); err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword("pw")
	d.AddUser(config.User{Username: "alice", Role: "pentester", PasswordHash: hash})
	gs := &Server{Repo: r, Auth: auth.New(d)}
	if err := gs.Setup(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/git/", gs.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r, d
}

// The credential cache must not outlive the account: a deleted user or a
// changed password stops working at once.
func TestCacheFollowsAccountChanges(t *testing.T) {
	srv, _, d := setupDB(t)
	get := func(pw string) int {
		req, _ := http.NewRequest("GET", srv.URL+"/git/yars/info/refs?service=git-upload-pack", nil)
		req.SetBasicAuth("alice", pw)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := get("pw"); c != 200 {
		t.Fatalf("login %d", c)
	}
	h, _ := auth.HashPassword("new")
	d.SetPassword("alice", h)
	if c := get("pw"); c != 401 {
		t.Fatalf("old password still works from the cache: %d", c)
	}
	if c := get("new"); c != 200 {
		t.Fatalf("new password %d", c)
	}
	d.DeleteUser("alice")
	if c := get("new"); c != 401 {
		t.Fatalf("deleted account still works from the cache: %d", c)
	}
}

func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=alice", "-c", "user.email=a@a", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestAuthRequired(t *testing.T) {
	srv, _ := setup(t)
	get := func(path, user, pw string) int {
		req, _ := http.NewRequest("GET", srv.URL+path, nil)
		if user != "" {
			req.SetBasicAuth(user, pw)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == 401 && resp.Header.Get("WWW-Authenticate") == "" {
			t.Error("401 without WWW-Authenticate")
		}
		return resp.StatusCode
	}
	refs := "/git/yars/info/refs?service=git-upload-pack"
	if c := get(refs, "", ""); c != 401 {
		t.Errorf("no auth: %d", c)
	}
	if c := get(refs, "alice", "nope"); c != 401 {
		t.Errorf("bad password: %d", c)
	}
	if c := get(refs, "alice", "pw"); c != 200 {
		t.Errorf("good auth: %d", c)
	}
	if c := get("/git/other/info/refs?service=git-upload-pack", "alice", "pw"); c != 404 {
		t.Errorf("other repo: %d", c)
	}
}

func TestSetupHardening(t *testing.T) {
	_, r := setup(t)
	for k, want := range map[string]string{"receive.fsckObjects": "true", "core.hooksPath": filepath.Join(r.Dir, ".git", "hooks")} {
		out, err := exec.Command("git", "-C", r.Dir, "config", "--local", k).Output()
		if got := strings.TrimSpace(string(out)); err != nil || got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	gs := &Server{Repo: r, InheritEnv: []string{"YARS_AI_KEY"}}
	if env := gs.inherit(); !slices.Contains(env, "YARS_AI_KEY") || !slices.Contains(env, "HTTPS_PROXY") {
		t.Errorf("inherited env %v", env)
	}
}

func TestCloneAndPush(t *testing.T) {
	srv, r := setup(t)
	dst := filepath.Join(t.TempDir(), "clone")
	url := strings.Replace(srv.URL, "http://", "http://alice:pw@", 1) + "/git/yars"
	out, err := exec.Command("git", "clone", "-q", url, dst).CombinedOutput()
	if err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dst, "engagements", "acme", "engagement.yaml")); err != nil {
		t.Fatal("clone lacks engagement")
	}
	os.WriteFile(filepath.Join(dst, "engagements", "acme", "notes.txt"), []byte("hi\n"), 0o644)
	if s, _ := exec.Command("git", "-C", r.Dir, "config", "core.hooksPath").Output(); len(s) == 0 {
		t.Fatal("hooksPath not set")
	}
	gitCmd(t, dst, "add", "-A")
	gitCmd(t, dst, "commit", "-qm", "note")
	before, _ := r.Head()
	gitCmd(t, dst, "push", "-q", "origin", "HEAD")
	after, _ := r.Head()
	if before == after {
		t.Fatal("server HEAD did not move")
	}
	if b, err := os.ReadFile(filepath.Join(r.Dir, "engagements", "acme", "notes.txt")); err != nil || string(b) != "hi\n" {
		t.Fatalf("working tree not updated: %v", err)
	}
}
