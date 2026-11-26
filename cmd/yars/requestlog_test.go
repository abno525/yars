package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/web"
)

// served is a data folder served the way yars serve serves it.
type served struct {
	dir string
	url string
	st  *store.Store
	d   *db.DB
	srv *web.Server
}

// serveLogged sets up a data folder and serves it through the steps of yars
// serve (startConfig, prepareData, serverParts), every part logging to lg:
// what a test reads in the log is what the service would write. exe is the
// binary the push hook runs. The accounts alice (pentester) and dora
// (director, admin) have the password pw; the engagement acme is alice's.
func serveLogged(t *testing.T, lg *slog.Logger, exe, pw string) *served {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := startConfig(r)
	if err != nil {
		t.Fatal(err)
	}
	d, st, err := prepareData(r, cfg, lg)
	if err != nil {
		t.Fatal(err)
	}
	hash := testHash(t, pw)
	for _, u := range []config.User{{Username: "alice", Role: "pentester", PasswordHash: hash}, {Username: "dora", Role: "director", PasswordHash: hash, IsAdmin: true}} {
		if err := d.AddUser(u); err != nil {
			t.Fatal(err)
		}
	}
	srv, err := serverParts(r, cfg, d, st, lg, exe, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, gitrepo.Author{Name: "dora", Email: "dora@yars.local"}); err != nil {
		t.Fatal(err)
	}
	if err := d.AddMembers("acme", "alice"); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
		st.StopChecks()
		st.WaitChecks()
		d.Close()
	})
	return &served{dir: dir, url: ts.URL, st: st, d: d, srv: srv}
}

// The git and MCP endpoints get the same line a request as the website: a
// fixed word for the kind of git request, the tool and the code of an MCP
// call (it always answers 200), who asked, and the token by its ID. Neither
// a password nor a token's value is in a line.
func TestRequestLineGitAndMCP(t *testing.T) {
	const pw = "zqgitpass7f3kq"
	lg, out := logs.NewRecorder()
	s := serveLogged(t, lg, "yars", pw)
	if _, err := s.st.CreateFinding("acme", "SQL injection", gitrepo.Author{Name: "alice", Email: "alice@yars.local"}); err != nil {
		t.Fatal(err)
	}
	tokens := auth.NewTokens(s.d)
	gitTok, gitInfo, err := tokens.Create("alice", "alice", db.TokenSpec{Kind: db.TokenGit, Scopes: []string{db.ScopeAll}})
	if err != nil {
		t.Fatal(err)
	}
	mcpTok, mcpInfo, err := tokens.Create("alice", "alice", db.TokenSpec{Kind: db.TokenMCP, Scopes: []string{db.ScopeAll}})
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder // every line of the test
	do := func(method, path, body string, set func(*http.Request)) (*http.Response, logs.Record) {
		t.Helper()
		out.Reset()
		req, _ := http.NewRequest(method, s.url+path, strings.NewReader(body))
		if set != nil {
			set(req)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		l := out.With("request")
		all.WriteString(out.Text())
		if len(l) != 1 || l[0].Str("req") != resp.Header.Get("X-Request-ID") || l[0].Str("req") == "" {
			t.Fatalf("%s %s: want one request line with the response's ID, got:\n%s", method, path, out.Text())
		}
		return resp, l[0]
	}
	refs := "/git/e/acme/info/refs?service=git-upload-pack"

	// git asks without credentials first: 401, no user, an info line
	resp, l := do("GET", refs, "", nil)
	if resp.StatusCode != 401 || l.Str("route") != "git info/refs" || l.Has("user") || l.Has("eng") || l.Level != slog.LevelInfo {
		t.Errorf("git without credentials: %s", l)
	}
	// with the password: the account and the engagement
	resp, l = do("GET", refs, "", func(r *http.Request) { r.SetBasicAuth("alice", pw) })
	if resp.StatusCode != 200 || l.Str("route") != "git info/refs" || l.Str("user") != "alice" || l.Str("eng") != "acme" || l.Has("token") || l.Str("status") != "200" {
		t.Errorf("git with a password: %s", l)
	}
	// with a token: its ID, a number
	resp, l = do("GET", refs, "", func(r *http.Request) { r.SetBasicAuth("alice", gitTok) })
	if id, ok := l.Attrs["token"].(int64); resp.StatusCode != 200 || !ok || id != gitInfo.ID || l.Str("user") != "alice" {
		t.Errorf("git with a token: %s", l)
	}
	// a wrong password: the name the client gave is not on the request line
	resp, l = do("GET", refs, "", func(r *http.Request) { r.SetBasicAuth("zqgituser7f3kq", "zqwrong7f3kq") })
	if resp.StatusCode != 401 || l.Has("user") {
		t.Errorf("git with a wrong password: %s", l)
	}

	// MCP: the tool and the code of its answer
	call := func(tool, args string) logs.Record {
		t.Helper()
		resp, l := do("POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+args+`}}`, func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+mcpTok)
			r.Header.Set("Content-Type", "application/json")
		})
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d", tool, resp.StatusCode)
		}
		return l
	}
	l = call("read_finding", `{"engagement":"acme","finding":"F-001"}`)
	if id, ok := l.Attrs["token"].(int64); l.Str("route") != "/mcp" || l.Str("tool") != "read_finding" || l.Str("code") != "ok" ||
		l.Str("eng") != "acme" || l.Str("finding") != "F-001" || l.Str("user") != "alice" || !ok || id != mcpInfo.ID {
		t.Errorf("mcp read_finding: %s", l)
	}
	l = call("read_finding", `{"engagement":"acme","finding":"F-099"}`)
	if l.Str("tool") != "read_finding" || l.Str("code") != "not_found" || l.Str("status") != "200" {
		t.Errorf("mcp read_finding of no finding: %s", l)
	}
	// a tool that does not exist is a client's word: not on the line
	if l = call("zqtool7f3kq", `{}`); l.Has("tool") || l.Has("code") {
		t.Errorf("mcp unknown tool: %s", l)
	}
	// no token: 401 and no user
	resp, l = do("POST", "/mcp", `{}`, func(r *http.Request) { r.Header.Set("Authorization", "Bearer zqbearer7f3kq") })
	if resp.StatusCode != 401 || l.Has("user") || l.Has("token") {
		t.Errorf("mcp without a token: %s", l)
	}
	if !strings.Contains(all.String(), "git login failed") {
		t.Errorf("no failed-login line:\n%s", all.String())
	}
	for _, private := range []string{pw, gitTok, mcpTok, "zqwrong7f3kq", "zqtool7f3kq", "zqbearer7f3kq", "service="} {
		if strings.Contains(all.String(), private) {
			t.Errorf("the log holds %q:\n%s", private, all.String())
		}
	}
}
