package gitserve

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/rules"
	"yars/internal/store"
)

const lintRule = "- id: title-no-trailing-dot\n  target: title\n  regex_forbid: '\\.$'\n  message: The title ends with a dot\n"

type lintEnv struct {
	srv  *httptest.Server
	st   *store.Store
	d    *db.DB
	r    *gitrepo.Repo
	raw  []byte // a finding of acme whose title ends with a dot
	dir  string // its folder
	gs   *Server
	tokR string // alice's read-only git token
	tokO string // alice's git token limited to the other engagement
}

// setupLint is setupDB with rules, a finding and the lint endpoint.
func setupLint(t *testing.T) *lintEnv {
	t.Helper()
	data := t.TempDir()
	r, err := gitrepo.Init(data)
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	st := store.New(r, config.Default(), d)
	who := gitrepo.Author{Name: "a", Email: "a@a"}
	for _, id := range []string{"acme", "other"} {
		if err := st.CreateEngagement(store.Engagement{ID: id, Name: strings.ToUpper(id)}, who); err != nil {
			t.Fatal(err)
		}
	}
	rd := filepath.Join(data, ".yars", "rules")
	os.MkdirAll(rd, 0o755)
	if err := os.WriteFile(filepath.Join(rd, "style.yaml"), []byte(lintRule), 0o644); err != nil {
		t.Fatal(err)
	}
	st.Linter = rules.NewEngine(rd, config.Default())
	hash := testHash(t, "pw")
	d.AddUser(config.User{Username: "alice", Role: "pentester", PasswordHash: hash})
	d.AddUser(config.User{Username: "pen2", Role: "pentester", PasswordHash: hash})
	d.AddMembers("acme", "alice")
	d.AddMembers("other", "alice")
	ref, err := st.CreateFinding("acme", "SQL injection", gitrepo.Author{Name: "alice", Email: "alice@yars.local"})
	if err != nil {
		t.Fatal(err)
	}
	raw := strings.Replace(string(ref.F.Bytes()), "title: SQL injection\n", "title: SQL injection.\n", 1)
	if raw == string(ref.F.Bytes()) {
		t.Fatalf("no title line in:\n%s", raw)
	}
	tk := auth.NewTokens(d)
	tokR, _, err := tk.Create("alice", "alice", db.TokenSpec{Kind: db.TokenGit, Scopes: []string{db.ScopeRead}, Engagements: []string{"acme"}})
	if err != nil {
		t.Fatal(err)
	}
	tokO, _, err := tk.Create("alice", "alice", db.TokenSpec{Kind: db.TokenGit, Scopes: []string{db.ScopeAll}, Engagements: []string{"other"}})
	if err != nil {
		t.Fatal(err)
	}
	gs := &Server{Repo: r, Auth: auth.New(d), Tokens: tk, CanSee: st.CanSee, Sync: st.SyncPointers, Invalidate: st.Invalidate, Lint: st.LintContent}
	if err := gs.Setup(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/git/", gs.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &lintEnv{srv: srv, st: st, d: d, r: r, raw: []byte(raw), dir: ref.Dir, gs: gs, tokR: tokR, tokO: tokO}
}

// post sends body to the lint URL of eng as user/pw ("" user: no login).
func (e *lintEnv) post(t *testing.T, method, eng, user, pw string, body []byte) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+"/git/e/"+eng+"/lint", bytes.NewReader(body))
	if user != "" {
		req.SetBasicAuth(user, pw)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

type lintAnswer struct {
	Violations []struct{ Rule, Level, Message, Target, Quote string }
	Error      string
}

func TestLintEndpointReturnsViolations(t *testing.T) {
	e := setupLint(t)
	resp, body := e.post(t, "POST", "acme", "alice", "pw", e.raw)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%d %s: %s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}
	var a lintAnswer
	if err := json.Unmarshal([]byte(body), &a); err != nil {
		t.Fatal(err)
	}
	if len(a.Violations) != 1 || a.Violations[0].Rule != "title-no-trailing-dot" || a.Violations[0].Level != "error" || a.Violations[0].Message != "The title ends with a dot" || a.Violations[0].Target != "title" {
		t.Fatalf("answer %+v", a)
	}
	// a clean finding: an empty list, not null
	clean := strings.Replace(string(e.raw), "title: SQL injection.\n", "title: SQL injection\n", 1)
	if _, body := e.post(t, "POST", "acme", "alice", "pw", []byte(clean)); !strings.Contains(body, `"violations":[]`) {
		t.Fatalf("clean: %s", body)
	}
}

func TestLintEndpointNeedsLogin(t *testing.T) {
	e := setupLint(t)
	resp, _ := e.post(t, "POST", "acme", "", "", e.raw)
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") == "" {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if resp, _ := e.post(t, "POST", "acme", "alice", "nope", e.raw); resp.StatusCode != 401 {
		t.Fatalf("bad password: %d", resp.StatusCode)
	}
	// without a login an unknown engagement looks like any other
	if resp, _ := e.post(t, "POST", "nope", "", "", e.raw); resp.StatusCode != 401 {
		t.Fatalf("unknown engagement without a login: %d", resp.StatusCode)
	}
	// an account that must set a new password first may not lint either
	e.d.AddUser(config.User{Username: "newbie", Role: "pentester", PasswordHash: testHash(t, "pw"), MustChange: true})
	e.d.AddMembers("acme", "newbie")
	if resp, body := e.post(t, "POST", "acme", "newbie", "pw", e.raw); resp.StatusCode != 403 || strings.Contains(body, "violations") {
		t.Fatalf("must change: %d %s", resp.StatusCode, body)
	}
}

// A body sent without a length (chunked) is read like any other.
func TestLintEndpointChunked(t *testing.T) {
	e := setupLint(t)
	pr, pw := io.Pipe()
	go func() { pw.Write(e.raw); pw.Close() }()
	req, _ := http.NewRequest("POST", e.srv.URL+"/git/e/acme/lint", pr)
	req.SetBasicAuth("alice", "pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	// a pipe has no length, so the client sends it chunked
	if resp.StatusCode != 200 || !strings.Contains(string(b), "title-no-trailing-dot") || req.ContentLength > 0 {
		t.Fatalf("%d %d: %s", resp.StatusCode, req.ContentLength, b)
	}
}

// Review focus 3: someone off the team gets the clone's answer, and an
// unknown engagement the same as for a clone.
func TestLintEndpointTeamOnly(t *testing.T) {
	e := setupLint(t)
	clone := status(t, "GET", e.srv.URL+"/git/e/acme/info/refs?service=git-upload-pack", "pen2", "pw")
	resp, body := e.post(t, "POST", "acme", "pen2", "pw", e.raw)
	if resp.StatusCode != 403 || clone != 403 || strings.Contains(body, "violations") {
		t.Fatalf("lint %d, clone %d: %s", resp.StatusCode, clone, body)
	}
	if resp, _ := e.post(t, "POST", "nope", "alice", "pw", e.raw); resp.StatusCode != 404 {
		t.Fatalf("unknown engagement: %d", resp.StatusCode)
	}
}

// Review focus 4: nothing is stored: no commit, no check run, no chat.
func TestLintEndpointStoresNothing(t *testing.T) {
	e := setupLint(t)
	count := func(table string) int {
		var n int
		if err := e.d.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	er, err := gitrepo.Open(filepath.Join(e.r.Dir, "engagements", "acme"))
	if err != nil {
		t.Fatal(err)
	}
	head := func() string {
		h, err := er.Head()
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	h0, runs, chat, main0 := head(), count("check_runs"), count("chat"), mustHead(t, e.r)
	if resp, body := e.post(t, "POST", "acme", "alice", "pw", e.raw); resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if head() != h0 || count("check_runs") != runs || count("chat") != chat || mustHead(t, e.r) != main0 {
		t.Fatal("the lint stored something")
	}
	if got, err := e.st.Finding("acme", e.dir); err != nil || got.F.Meta.Title != "SQL injection" {
		t.Fatalf("the finding changed: %+v %v", got.F.Meta, err)
	}
}

func mustHead(t *testing.T, r *gitrepo.Repo) string {
	t.Helper()
	h, err := r.Head()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestLintEndpointUnparseable(t *testing.T) {
	e := setupLint(t)
	resp, body := e.post(t, "POST", "acme", "alice", "pw", []byte("---\ntitle: [\n---\n"))
	var a lintAnswer
	json.Unmarshal([]byte(body), &a)
	if resp.StatusCode != 422 || a.Error == "" || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%d: %s", resp.StatusCode, body)
	}
}

func TestLintEndpointTooLarge(t *testing.T) {
	e := setupLint(t)
	big := append(append([]byte{}, e.raw...), bytes.Repeat([]byte("x"), LintMaxBody)...)
	if resp, body := e.post(t, "POST", "acme", "alice", "pw", big); resp.StatusCode != 413 {
		t.Fatalf("%d: %s", resp.StatusCode, body)
	}
}

func TestLintEndpointGetIs405(t *testing.T) {
	e := setupLint(t)
	resp, _ := e.post(t, "GET", "acme", "alice", "pw", nil)
	if resp.StatusCode != 405 || resp.Header.Get("Allow") != "POST" {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("Allow"))
	}
}

func TestLintEndpointRestrictedToken(t *testing.T) {
	e := setupLint(t)
	if resp, _ := e.post(t, "POST", "acme", "alice", e.tokO, e.raw); resp.StatusCode != 403 {
		t.Fatalf("token for another engagement: %d", resp.StatusCode)
	}
	if resp, body := e.post(t, "POST", "acme", "alice", e.tokR, e.raw); resp.StatusCode != 200 || !strings.Contains(body, "title-no-trailing-dot") {
		t.Fatalf("read-only token: %d %s", resp.StatusCode, body)
	}
}

// No Lint func set: the path is not there, for any method.
func TestLintEndpointOff(t *testing.T) {
	e := setupLint(t)
	e.gs.Lint = nil
	for _, m := range []string{"POST", "GET"} {
		if resp, _ := e.post(t, m, "acme", "alice", "pw", e.raw); resp.StatusCode != 404 {
			t.Fatalf("%s: %d", m, resp.StatusCode)
		}
	}
}

// A client that stops sending the body part way does not hold the handler:
// the body has a read deadline (lifted again before the rules run).
func TestLintEndpointStalledBody(t *testing.T) {
	e := setupLint(t)
	old := lintReadTimeout
	lintReadTimeout = 300 * time.Millisecond
	defer func() { lintReadTimeout = old }()
	conn, err := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("alice:pw"))
	fmt.Fprintf(conn, "POST /git/e/acme/lint HTTP/1.1\r\nHost: x\r\nAuthorization: Basic %s\r\nContent-Length: 1000\r\n\r\n---\n", auth)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	b, _ := io.ReadAll(conn) // the server answers or closes
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("held for %v: %q", took, b)
	}
	if strings.Contains(string(b), "violations") {
		t.Fatalf("a part of a body was checked: %q", b)
	}
	// a body announced over the limit is refused before it is read
	big := e.raw
	req, _ := http.NewRequest("POST", e.srv.URL+"/git/e/acme/lint", bytes.NewReader(big))
	req.SetBasicAuth("alice", "pw")
	req.ContentLength = LintMaxBody + 1
	req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(big), bytes.NewReader(make([]byte, LintMaxBody+1-len(big)))))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatalf("announced over the limit: %d", resp.StatusCode)
	}
}
