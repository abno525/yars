package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/index"
	"yars/internal/store"
)

var (
	hashOnce sync.Once
	pwHash   string
)

type env struct {
	srv  *Server
	h    http.Handler
	dir  string
	toks map[string]string
}

func setup(t *testing.T) *env {
	t.Helper()
	hashOnce.Do(func() { pwHash, _ = auth.HashPassword("pw") })
	dir := t.TempDir()
	r, err := gitrepo.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	st := store.New(r, cfg)
	a := gitrepo.Author{Name: "alice", Email: "alice@yars.local"}
	if err := st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME Web"}, a); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFinding("acme", "SQL injection", a); err != nil {
		t.Fatal(err)
	}
	users := []config.User{
		{Username: "alice", Role: "pentester", PasswordHash: pwHash},
		{Username: "bob", Role: "reviewer", PasswordHash: pwHash},
		{Username: "dora", Role: "director", PasswordHash: pwHash},
	}
	au := auth.New(users)
	s := &Server{Store: st, Index: index.New(st, r), Auth: au, Cfg: cfg}
	e := &env{srv: s, h: s.Handler(), dir: dir, toks: map[string]string{}}
	for _, u := range users {
		tok, ok := au.Login(u.Username, "pw")
		if !ok {
			t.Fatal("login failed")
		}
		e.toks[u.Username] = tok
	}
	return e
}

func (e *env) do(t *testing.T, user, method, path string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if user != "" {
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks[user]})
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *env) lastCommit(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "-C", e.dir, "log", "-1", "--format=%an|%s").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestEngagementTable(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "GET", "/e/acme", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	b := rec.Body.String()
	if !strings.Contains(b, "SQL injection") || !strings.Contains(b, "F-001") || !strings.Contains(b, "ACME Web") {
		t.Fatalf("body missing content:\n%s", b)
	}
}

func TestTablePartialOnHX(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "GET", "/e/acme?sort=status", nil, map[string]string{"HX-Request": "true"})
	b := rec.Body.String()
	if rec.Code != 200 || strings.Contains(b, "<html") || !strings.Contains(b, "F-001") {
		t.Fatalf("code %d body:\n%s", rec.Code, b)
	}
}

func TestFindingPageSections(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "GET", "/e/acme/f/F-001-sql-injection", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	for _, s := range config.Default().Sections {
		if !strings.Contains(rec.Body.String(), "<h2>"+s+"</h2>") {
			t.Fatalf("missing section %s", s)
		}
	}
}

func TestTraversal404(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/e/..%2F..%2Fetc/f/x", "/e/acme/f/..%2F..%2F..", "/e/nope"} {
		if rec := e.do(t, "alice", "GET", p, nil, nil); rec.Code != 404 {
			t.Fatalf("%s: code %d", p, rec.Code)
		}
	}
}

func TestUnauthedRedirect(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "", "GET", "/", nil, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("code %d loc %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestLoginFlow(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"pw"}}, nil)
	if rec.Code != http.StatusSeeOther || len(rec.Result().Cookies()) == 0 {
		t.Fatalf("code %d", rec.Code)
	}
	rec = e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"bad"}}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login code %d", rec.Code)
	}
}

func TestMarkdownNoRawHTML(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Impact", "<script>alert(1)</script>", "", gitrepo.Author{Name: "x", Email: "x@x"}); err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, "alice", "GET", "/e/acme/f/F-001-sql-injection", nil, nil)
	if strings.Contains(rec.Body.String(), "<script>alert(1)") {
		t.Fatal("raw HTML rendered")
	}
}
