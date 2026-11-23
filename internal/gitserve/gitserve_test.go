package gitserve

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

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
	return setupWith(t, nil)
}

// setupWith is setupDB with a hook told about each invalidation.
func setupWith(t *testing.T, seen func(eng string)) (*httptest.Server, *gitrepo.Repo, *db.DB) {
	t.Helper()
	return setupFull(t, seen, nil)
}

// setupServer is setupDB with a change to the git server before it starts.
func setupServer(t *testing.T, change func(*Server)) (*httptest.Server, *gitrepo.Repo, *db.DB) {
	t.Helper()
	return setupFull(t, nil, change)
}

func setupFull(t *testing.T, seen func(eng string), change func(*Server)) (*httptest.Server, *gitrepo.Repo, *db.DB) {
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
	hash := testHash(t, "pw")
	d.AddUser(config.User{Username: "alice", Role: "pentester", PasswordHash: hash})
	d.AddUser(config.User{Username: "pen2", Role: "pentester", PasswordHash: hash})
	d.AddMembers("acme", "alice") // pen2 is on no team
	gs := &Server{Repo: r, Auth: auth.New(d), Tokens: auth.NewTokens(d), CanSee: st.CanSee, Sync: st.SyncPointers, Invalidate: func(eng string) {
		if seen != nil {
			seen(eng)
		}
		st.Invalidate(eng)
	}}
	if change != nil {
		change(gs)
	}
	if err := gs.Setup(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/git/", gs.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, r, d
}

// Many first requests at once to an engagement made after the server
// started all get through: the repository is set up once, the others wait
// for it, none fails on git's config lock (backlog, M11).
func TestFirstRequestsSetUpOnce(t *testing.T) {
	var setups atomic.Int32
	srv, r, d := setupServer(t, func(gs *Server) {
		gs.beforeSetup = func(dir string) {
			if filepath.Base(dir) == "fresh" {
				setups.Add(1)
				time.Sleep(50 * time.Millisecond)
			}
		}
	})
	st := store.New(r, config.Default(), d)
	if err := st.CreateEngagement(store.Engagement{ID: "fresh", Name: "Fresh"}, gitrepo.Author{Name: "a", Email: "a@a"}); err != nil {
		t.Fatal(err)
	}
	d.AddMembers("fresh", "alice")
	// the login once, on the main repository: the requests below share it
	warm, _ := http.NewRequest("GET", srv.URL+"/git/yars/info/refs?service=git-upload-pack", nil)
	warm.SetBasicAuth("alice", "pw")
	if resp, err := http.DefaultClient.Do(warm); err != nil || resp.StatusCode != 200 {
		t.Fatalf("login: %v", err)
	} else {
		resp.Body.Close()
	}
	var wg sync.WaitGroup
	codes := make(chan int, 24)
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("GET", srv.URL+"/git/e/fresh/info/refs?service=git-upload-pack", nil)
			req.SetBasicAuth("alice", "pw")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				codes <- 0
				return
			}
			resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != 200 {
			t.Fatalf("a first request got %d", c)
		}
	}
	if n := setups.Load(); n != 1 {
		t.Fatalf("set up %d times", n)
	}
}

// A repository counts as set up only while the hook it got is there: one
// whose folder was replaced while the server ran (no hook) is set up again
// on its next request, so no push skips the checks (backlog, M11).
func TestSetupAgainWithoutHook(t *testing.T) {
	srv, r, _ := setupServer(t, func(gs *Server) { gs.HookCmd = "/bin/false" })
	hook := filepath.Join(r.Dir, "engagements", "acme", ".git", "hooks", "pre-receive")
	if _, err := os.Stat(hook); err != nil {
		t.Fatalf("no hook after the start: %v", err)
	}
	os.Remove(hook)
	req, _ := http.NewRequest("GET", srv.URL+"/git/e/acme/info/refs?service=git-upload-pack", nil)
	req.SetBasicAuth("alice", "pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", err, resp)
	}
	resp.Body.Close()
	if _, err := os.Stat(hook); err != nil {
		t.Fatal("the hook was not written again")
	}
}

// Failed git logins count toward the lockout (D27) as the website's do:
// after five, even the right password is refused for a while (M34 review).
func TestGitLoginLockout(t *testing.T) {
	srv, _, _ := setupDB(t)
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
	for range 5 {
		if c := get("wrong"); c != 401 {
			t.Fatalf("a wrong password: %d", c)
		}
	}
	if c := get("pw"); c != 401 {
		t.Fatalf("the right password after five failures: %d", c)
	}
}

// Many first requests of one login at once (a clone) all get through: the
// same credentials are checked once while that check runs, instead of each
// counting as a login attempt in flight, past the lockout's limit refused.
// Wrong passwords at once still count one attempt each: they lock the name
// out, and even the right password is refused after them.
func TestParallelFirstLogins(t *testing.T) {
	srv, _, d := setupDB(t)
	// a hash slow enough that the checks overlap
	h, err := bcrypt.GenerateFromPassword([]byte("pw"), 10)
	if err != nil {
		t.Fatal(err)
	}
	d.AddUser(config.User{Username: "carl", Role: "pentester", PasswordHash: string(h)})
	d.AddUser(config.User{Username: "dave", Role: "pentester", PasswordHash: string(h)})
	get := func(user, pw string) int {
		req, _ := http.NewRequest("GET", srv.URL+"/git/yars/info/refs?service=git-upload-pack", nil)
		req.SetBasicAuth(user, pw)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	atOnce := func(user, pw string) []int {
		var wg sync.WaitGroup
		codes := make([]int, 24)
		for i := range codes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				codes[i] = get(user, pw)
			}()
		}
		wg.Wait()
		return codes
	}
	codes := atOnce("carl", "pw")
	for _, c := range codes {
		if c != 200 {
			t.Fatalf("parallel first logins with the right password: %v", codes)
		}
	}
	for _, c := range atOnce("dave", "wrong") {
		if c != 401 {
			t.Fatalf("a wrong password: %d", c)
		}
	}
	if c := get("dave", "pw"); c != 401 {
		t.Fatalf("the right password after wrong ones at once: %d", c)
	}
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
	h := testHash(t, "new")
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

// Expired logins leave the credential cache on the next miss: it does not
// grow with every password ever used.
func TestCredCachePurged(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	d.AddUser(config.User{Username: "alice", Role: "pentester", PasswordHash: testHash(t, "pw")})
	s := &Server{Auth: auth.New(d)}
	s.cache = map[string]cached{
		"old":   {config.User{Username: "x"}, time.Now().Add(-time.Minute)},
		"fresh": {config.User{Username: "y"}, time.Now().Add(time.Minute)},
	}
	s.check("alice", "wrong")
	if _, ok := s.cache["old"]; ok {
		t.Fatal("an expired login is still cached")
	}
	if _, ok := s.cache["fresh"]; !ok {
		t.Fatal("a valid login was purged")
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
	for _, p := range []string{"/git/other", "/git/e/nope", "/git/e/..", "/git/e/.git", "/git/e/-x"} {
		if c := get(p+"/info/refs?service=git-upload-pack", "alice", "pw"); c != 404 {
			t.Errorf("%s: %d", p, c)
		}
	}
	if c := get("/git/e/acme/info/refs?service=git-upload-pack", "alice", "pw"); c != 200 {
		t.Errorf("engagement repo: %d", c)
	}
	if c := get("/git/e/acme/info/refs?service=git-upload-pack", "", ""); c != 401 {
		t.Errorf("engagement repo without auth: %d", c)
	}
	// without a login nothing tells which engagements exist
	if c := get("/git/e/nope/info/refs?service=git-upload-pack", "", ""); c != 401 {
		t.Errorf("unknown engagement without auth: %d", c)
	}
	// engagement repos are reachable only through /git/e/<id> (which sets
	// them up with the push checks), never through the main repo's URL
	for _, p := range []string{"/git/yars/engagements/acme/info/refs?service=git-receive-pack", "/git/yars/engagements/acme/HEAD"} {
		if c := get(p, "alice", "pw"); c != 404 {
			t.Errorf("%s: %d", p, c)
		}
	}
}

// An engagement repo's hook names its engagement, so the hook never has to
// guess the repo from paths (which symlinks can make differ).
func TestEngagementHookNamesEngagement(t *testing.T) {
	_, r := setup(t)
	gs := &Server{Repo: r, HookCmd: "'/bin/yars' hook pre-receive --data '/d'"}
	if err := gs.Setup(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(r.Dir, "engagements", "acme", ".git", "hooks", "pre-receive"))
	if !strings.Contains(string(b), "--data '/d' --eng acme") {
		t.Fatalf("engagement hook:\n%s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(r.Dir, ".git", "hooks", "pre-receive")); strings.Contains(string(b), "--eng") {
		t.Fatalf("main hook names an engagement:\n%s", b)
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

// A push tells the store which repo moved (its HEAD cache); fetches don't.
func TestPushInvalidates(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv, _, _ := setupWith(t, func(e string) { mu.Lock(); seen = append(seen, e); mu.Unlock() })
	dst := filepath.Join(t.TempDir(), "clone")
	url := strings.Replace(srv.URL, "http://", "http://alice:pw@", 1) + "/git/e/acme"
	cmd := exec.Command("git", "clone", "-q", url, dst)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	mu.Lock()
	if len(seen) != 0 {
		t.Fatalf("fetch invalidated %v", seen)
	}
	mu.Unlock()
	os.WriteFile(filepath.Join(dst, "notes.txt"), []byte("hi\n"), 0o644)
	gitCmd(t, dst, "add", "-A")
	gitCmd(t, dst, "commit", "-qm", "note")
	gitCmd(t, dst, "push", "-q", "origin", "HEAD")
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(seen, []string{"acme"}) {
		t.Fatalf("invalidated %v", seen)
	}
}

// A push to an engagement repo runs inside Receive, named with the pusher;
// fetches don't.
func TestPushRunsInReceive(t *testing.T) {
	_, r, d := setupDB(t)
	st := store.New(r, config.Default(), d)
	var mu sync.Mutex
	var seen []string
	gs := &Server{Repo: r, Auth: auth.New(d), CanSee: st.CanSee, Receive: func(eng string, u config.User, serve func()) {
		mu.Lock()
		seen = append(seen, u.Username+"@"+eng)
		mu.Unlock()
		serve()
	}}
	mux := http.NewServeMux()
	mux.Handle("/git/", gs.Handler())
	own := httptest.NewServer(mux)
	t.Cleanup(own.Close)
	dst := filepath.Join(t.TempDir(), "clone")
	url := strings.Replace(own.URL, "http://", "http://alice:pw@", 1) + "/git/e/acme"
	cmd := exec.Command("git", "clone", "-q", url, dst)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	os.WriteFile(filepath.Join(dst, "notes.txt"), []byte("hi\n"), 0o644)
	gitCmd(t, dst, "add", "-A")
	gitCmd(t, dst, "commit", "-qm", "note")
	gitCmd(t, dst, "push", "-q", "origin", "HEAD")
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(seen, []string{"alice@acme"}) {
		t.Fatalf("receive %v", seen)
	}
	if b, err := os.ReadFile(filepath.Join(r.Dir, "engagements", "acme", "notes.txt")); err != nil || string(b) != "hi\n" {
		t.Fatal("push did not land")
	}
}

// A recursive clone of the main repo brings every engagement; a push goes to
// the engagement's own repository and updates the server's copy.
func TestCloneAndPush(t *testing.T) {
	srv, r := setup(t)
	dst := filepath.Join(t.TempDir(), "clone")
	url := strings.Replace(srv.URL, "http://", "http://alice:pw@", 1) + "/git/yars"
	cmd := exec.Command("git", "clone", "-q", "--recurse-submodules", url, dst)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	ed := filepath.Join(dst, "engagements", "acme")
	if _, err := os.Stat(filepath.Join(ed, "engagement.yaml")); err != nil {
		t.Fatal("clone lacks engagement")
	}
	gitCmd(t, ed, "switch", "-q", "main")
	os.WriteFile(filepath.Join(ed, "notes.txt"), []byte("hi\n"), 0o644)
	gitCmd(t, ed, "add", "-A")
	gitCmd(t, ed, "commit", "-qm", "note")
	er, _ := gitrepo.Open(filepath.Join(r.Dir, "engagements", "acme"))
	before, _ := er.Head()
	gitCmd(t, ed, "push", "-q", "origin", "HEAD")
	after, _ := er.Head()
	if before == after {
		t.Fatal("engagement repo HEAD did not move")
	}
	if b, err := os.ReadFile(filepath.Join(er.Dir, "notes.txt")); err != nil || string(b) != "hi\n" {
		t.Fatalf("working tree not updated: %v", err)
	}
	for _, d := range []string{r.Dir, er.Dir} {
		if s, _ := exec.Command("git", "-C", d, "config", "core.hooksPath").Output(); len(s) == 0 {
			t.Fatalf("hooksPath not set in %s", d)
		}
	}
	// the main repo's pointer follows on the next fetch of /git/yars
	gitCmd(t, dst, "pull", "-q", "--no-rebase")
	if link, _ := r.Gitlink("HEAD", "engagements/acme"); link != after {
		t.Fatalf("pointer %s, engagement at %s", link, after)
	}
}
