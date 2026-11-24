package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/index"
	"yars/internal/store"
)

// fresh is a server on a new data directory without any account.
func fresh(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	r, err := gitrepo.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	cfg := config.Default()
	st := store.New(r, cfg, d)
	s := &Server{Store: st, Index: index.New(st, r), Auth: auth.New(d), Cfg: cfg}
	return &env{srv: s, h: s.Handler(), dir: dir, toks: map[string]string{}}
}

// With no account, every page leads to /setup, which creates the first
// admin director once.
func TestFirstRun(t *testing.T) {
	e := fresh(t)
	for _, p := range []string{"/", "/login", "/inbox", "/e/acme", "/admin/users"} {
		rec := e.do(t, "", "GET", p, nil, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/setup" {
			t.Fatalf("GET %s: %d %q", p, rec.Code, rec.Header().Get("Location"))
		}
	}
	if rec := e.do(t, "", "GET", "/static/style.css", nil, nil); rec.Code == http.StatusSeeOther {
		t.Fatal("static files redirected")
	}
	rec := e.do(t, "", "GET", "/setup", nil, nil)
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, `name="username"`) || !strings.Contains(b, `name="repeat"`) || strings.Contains(b, `class="topbar"`) {
		t.Fatalf("setup form %d:\n%s", rec.Code, b)
	}
	for _, f := range []url.Values{
		{"username": {"dir1"}, "email": {"d@x.test"}, "password": {"long enough pw"}, "repeat": {"different pw"}},
		{"username": {"dir1"}, "email": {"d@x.test"}, "password": {"short"}, "repeat": {"short"}},
		{"username": {"bad name"}, "email": {"d@x.test"}, "password": {"long enough pw"}, "repeat": {"long enough pw"}},
	} {
		if rec := e.do(t, "", "POST", "/setup", f, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: %d", f, rec.Code)
		}
	}
	rec = e.do(t, "", "POST", "/setup", url.Values{"username": {"dir1"}, "email": {"d@x.test"}, "password": {"long enough pw"}, "repeat": {"long enough pw"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("setup %d %q", rec.Code, rec.Header().Get("Location"))
	}
	var tok string
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			tok = c.Value
		}
	}
	if tok == "" {
		t.Fatal("not signed in after setup")
	}
	u, ok := e.srv.Auth.Lookup("dir1")
	if !ok || u.Role != "director" || !u.IsAdmin || u.Email != "d@x.test" {
		t.Fatalf("first user %+v", u)
	}
	e.toks["dir1"] = tok
	if rec := e.do(t, "dir1", "GET", "/", nil, nil); rec.Code != 200 {
		t.Fatalf("home after setup %d", rec.Code)
	}
	for _, m := range []string{"GET", "POST"} {
		if rec := e.do(t, "", m, "/setup", url.Values{"username": {"evil"}, "password": {"long enough pw"}, "repeat": {"long enough pw"}}, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("%s /setup afterwards: %d", m, rec.Code)
		}
	}
	if rec := e.do(t, "", "GET", "/", nil, nil); rec.Header().Get("Location") != "/login" {
		t.Fatalf("after setup, logged out: %q", rec.Header().Get("Location"))
	}
}

// bcrypt takes at most 72 bytes: a longer new password is refused with the
// form's message (not a 500); 72 bytes are taken.
const (
	msgTooLong = "Password: at most 72 bytes"
	pw72       = "abcdefghij" + "abcdefghij" + "abcdefghij" + "abcdefghij" + "abcdefghij" + "abcdefghij" + "abcdefghij" + "ab"
	pw73       = pw72 + "x"
)

// refusedLong checks a form's answer to a password of 73 bytes.
func refusedLong(t *testing.T, what string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), msgTooLong) {
		t.Errorf("%s with 73 bytes: %d\n%s", what, rec.Code, rec.Body.String())
	}
}

func TestSetupPasswordAtMost72Bytes(t *testing.T) {
	e := fresh(t)
	refusedLong(t, "setup", e.do(t, "", "POST", "/setup", url.Values{"username": {"dir1"}, "password": {pw73}, "repeat": {pw73}}, nil))
	if rec := e.do(t, "", "POST", "/setup", url.Values{"username": {"dir1"}, "password": {pw72}, "repeat": {pw72}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("setup with 72 bytes: %d", rec.Code)
	}
}

// Settings › Account, Admin › Users and the first login's new password.
func TestPasswordAtMost72Bytes(t *testing.T) {
	e := setup(t)
	refusedLong(t, "settings", e.do(t, "alice", "POST", "/settings/password", url.Values{"current": {"pw"}, "new": {pw73}, "repeat": {pw73}}, nil))
	refusedLong(t, "admin add", e.do(t, "dora", "POST", "/admin/users", url.Values{"username": {"pen3"}, "role": {"pentester"}, "password": {pw73}}, nil))
	if rec := e.do(t, "dora", "POST", "/admin/users", url.Values{"username": {"pen3"}, "role": {"pentester"}, "password": {pw72}}, nil); rec.Code != 200 {
		t.Fatalf("admin add with 72 bytes: %d", rec.Code)
	}
	if res := e.loginAs(t, "pen3", pw72); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("login %d", res.StatusCode)
	}
	refusedLong(t, "first login", e.do(t, "pen3", "POST", "/password", url.Values{"new": {pw73}, "repeat": {pw73}}, nil))
	other := "z" + pw72[1:]
	if rec := e.do(t, "pen3", "POST", "/password", url.Values{"new": {other}, "repeat": {other}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("first login with 72 bytes: %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/settings/password", url.Values{"current": {"pw"}, "new": {pw72}, "repeat": {pw72}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("settings with 72 bytes: %d", rec.Code)
	}
}

// The login page stands alone (no top bar); a disabled account gets the
// same answer as a wrong password.
func TestLoginPage(t *testing.T) {
	e := setup(t)
	b := e.do(t, "", "GET", "/login", nil, nil).Body.String()
	if strings.Contains(b, `class="topbar"`) || !strings.Contains(b, `class="bare"`) || !strings.Contains(b, `class="logo big"`) {
		t.Fatalf("login page:\n%s", b)
	}
	wrong := e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"bad"}}, nil)
	e.srv.Store.DB().SetDisabled("bob", true)
	disabled := e.do(t, "", "POST", "/login", url.Values{"username": {"bob"}, "password": {"pw"}}, nil)
	if wrong.Code != http.StatusUnauthorized || disabled.Code != http.StatusUnauthorized {
		t.Fatalf("codes %d %d", wrong.Code, disabled.Code)
	}
	// the same page but for the username kept in the form
	same := strings.Replace(wrong.Body.String(), `value="alice"`, `value="bob"`, 1)
	if !strings.Contains(disabled.Body.String(), "Wrong username or password") || same != disabled.Body.String() {
		t.Fatal("a disabled account is told apart from a wrong password")
	}
	if rec := e.do(t, "", "GET", "/setup", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("setup with accounts: %d", rec.Code)
	}
}

// A clean login form has no error box or reserved space for one; after a
// failed attempt the box sits under the form, outside it.
func TestLoginErrorBox(t *testing.T) {
	e := setup(t)
	b := e.do(t, "", "GET", "/login", nil, nil).Body.String()
	if strings.Contains(b, `role="alert"`) || strings.Contains(b, "alertslot") {
		t.Fatalf("clean login has an error box or slot:\n%s", b)
	}
	b = e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"bad"}}, nil).Body.String()
	end, alert := strings.Index(b, "</form>"), strings.Index(b, `role="alert"`)
	if end < 0 || alert < end || !strings.Contains(b[alert:], "Wrong username or password") {
		t.Fatalf("error box not under the form:\n%s", b)
	}
}
