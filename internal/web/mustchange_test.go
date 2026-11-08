package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// login logs user in with pw through the login form and keeps the session.
func (e *env) loginAs(t *testing.T, user, pw string) *http.Response {
	t.Helper()
	rec := e.do(t, "", "POST", "/login", url.Values{"username": {user}, "password": {pw}}, nil)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "yars_session" && c.Value != "" {
			e.toks[user] = c.Value
		}
	}
	return rec.Result()
}

// D26: an account an admin created with a temporary password must set a
// new one on first login before anything else; until then every other page
// leads to the set-password page and every other write is refused.
func TestTemporaryPasswordMustBeChanged(t *testing.T) {
	e := setup(t)
	temp := "temporary-pass-1"
	if rec := e.do(t, "dora", "POST", "/admin/users", url.Values{"username": {"pen2"}, "role": {"pentester"}, "email": {"pen2@yars.local"}, "password": {temp}}, nil); rec.Code != 200 {
		t.Fatalf("add user %d", rec.Code)
	}
	if res := e.loginAs(t, "pen2", temp); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("login %d", res.StatusCode)
	}
	if rec := e.do(t, "pen2", "GET", "/inbox", nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/password" {
		t.Fatalf("a page before the change: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if rec := e.do(t, "pen2", "GET", "/e/acme/f/001/details", nil, map[string]string{"HX-Request": "true"}); rec.Header().Get("HX-Redirect") != "/password" {
		t.Fatalf("an htmx request: %d %v", rec.Code, rec.Header())
	}
	for _, p := range []string{"/settings/tokens", "/e/acme/f/001/chat", "/settings/password"} {
		if rec := e.do(t, "pen2", "POST", p, url.Values{"text": {"x"}, "name": {"t"}}, nil); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s before the change: %d", p, rec.Code)
		}
	}
	if rec := e.do(t, "pen2", "GET", "/events?eng=acme", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("events before the change: %d", rec.Code)
	}
	// git over HTTP does not take the temporary password either
	if _, ok := e.srv.Auth.Check("pen2", temp); ok {
		t.Fatal("git auth took a temporary password")
	}
	page := e.do(t, "pen2", "GET", "/password", nil, nil).Body.String()
	for _, want := range []string{"Set a new password", `name="new"`, `name="repeat"`, ">Set password</button>", "pen2"} {
		if !strings.Contains(page, want) {
			t.Fatalf("set-password page lacks %q:\n%s", want, page)
		}
	}
	if strings.Contains(page, `class="topbar"`) {
		t.Fatal("the set-password page has the top bar")
	}
	// board 1.3 First-Run frame 2: a 152px button, right in the card's
	// fields, not the login page's full-width bar
	if !strings.Contains(page, `<div class="barefoot"><button class="btn primary w152">Set password</button></div>`) ||
		strings.Contains(page, "barebtn") || strings.Index(page, `class="barefoot"`) > strings.Index(page, "</form>") {
		t.Fatalf("set-password button:\n%s", page)
	}
	for _, bad := range []url.Values{{"new": {temp}, "repeat": {temp}}, {"new": {"short"}, "repeat": {"short"}}, {"new": {"a-new-password-1"}, "repeat": {"a-new-password-2"}}} {
		if rec := e.do(t, "pen2", "POST", "/password", bad, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `class="barealert"`) {
			t.Errorf("bad new password %v: %d", bad, rec.Code)
		}
	}
	rec := e.do(t, "pen2", "POST", "/password", url.Values{"new": {"a-new-password-1"}, "repeat": {"a-new-password-1"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("set password %d %s", rec.Code, rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "yars_session" && c.Value != "" {
			e.toks["pen2"] = c.Value
		}
	}
	if rec := e.do(t, "pen2", "GET", "/inbox", nil, nil); rec.Code != 200 {
		t.Fatalf("inbox after the change: %d", rec.Code)
	}
	if _, ok := e.srv.Auth.Check("pen2", "a-new-password-1"); !ok {
		t.Fatal("git auth after the change")
	}
	if rec := e.do(t, "pen2", "GET", "/password", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("set-password page once done: %d", rec.Code)
	}
	// an admin's reset asks again
	if rec := e.do(t, "dora", "POST", "/admin/users/pen2/reset", nil, nil); rec.Code != 200 {
		t.Fatalf("reset %d", rec.Code)
	}
	if u, _, _ := e.srv.Store.DB().User("pen2"); !u.MustChange {
		t.Fatal("reset did not ask for a new password")
	}
}

// Accounts made by the first-run setup, the seed or the CLI are not asked.
func TestOtherAccountsNotAsked(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "alice", "GET", "/inbox", nil, nil); rec.Code != 200 {
		t.Fatalf("alice %d", rec.Code)
	}
	if rec := e.do(t, "alice", "GET", "/password", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("set-password page without a temporary password: %d", rec.Code)
	}
}
