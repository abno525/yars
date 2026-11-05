package web

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/store"
)

// The user name in the header opens the settings page; it shows the role
// read-only and the admin flag.
func TestSettingsPage(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/", nil, nil).Body.String()
	if !strings.Contains(b, `href="/settings"`) {
		t.Fatal("user name does not link to the settings")
	}
	rec := e.do(t, "alice", "GET", "/settings", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("settings %d", rec.Code)
	}
	b = rec.Body.String()
	if !strings.Contains(b, `class="who on"`) || strings.Contains(b, `<a class="on"`) {
		t.Fatal("settings page: the user name must be the one active nav item")
	}
	if !strings.Contains(b, `<span class="tag role">pentester</span>`) || strings.Contains(b, `<span class="tag adminflag">`) {
		t.Fatalf("alice's roles:\n%s", b)
	}
	if strings.Contains(b, `name="role"`) {
		t.Fatal("role is editable on the settings page")
	}
	if b := e.do(t, "dora", "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, `<span class="tag adminflag">admin</span>`) {
		t.Fatal("dora's admin flag not shown (class adminflag: .admin is the admin page grid)")
	}
	if rec := e.do(t, "", "GET", "/settings", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("logged out: %d", rec.Code)
	}
}

func TestSettingsEmailAndPassword(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "alice", "POST", "/settings/account", url.Values{"email": {"alice@acme.test"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("email %d", rec.Code)
	}
	if u, _ := e.srv.Auth.Lookup("alice"); u.Email != "alice@acme.test" {
		t.Fatalf("email %q", u.Email)
	}
	if rec := e.do(t, "alice", "POST", "/settings/account", url.Values{"email": {"not an email"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad email %d", rec.Code)
	}
	bad := []url.Values{
		{"current": {"wrong"}, "new": {"long enough pw"}, "repeat": {"long enough pw"}},
		{"current": {"pw"}, "new": {"long enough pw"}, "repeat": {"other"}},
		{"current": {"pw"}, "new": {"short"}, "repeat": {"short"}},
	}
	for _, f := range bad {
		if rec := e.do(t, "alice", "POST", "/settings/password", f, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: %d", f, rec.Code)
		}
	}
	rec := e.do(t, "alice", "POST", "/settings/password", url.Values{"current": {"pw"}, "new": {"long enough pw"}, "repeat": {"long enough pw"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("change %d", rec.Code)
	}
	// the other sessions end; this browser gets a new one
	var fresh string
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			fresh = c.Value
		}
	}
	if fresh == "" {
		t.Fatal("no new session after the change")
	}
	if r := e.do(t, "alice", "GET", "/", nil, nil); r.Code != http.StatusSeeOther {
		t.Fatalf("old session still valid: %d", r.Code)
	}
	e.toks["alice"] = fresh
	if r := e.do(t, "alice", "GET", "/", nil, nil); r.Code != 200 {
		t.Fatalf("new session: %d", r.Code)
	}
	if _, ok := e.srv.Auth.Check("alice", "long enough pw"); !ok {
		t.Fatal("new password does not work")
	}
}

var secretRe = regexp.MustCompile(`yars_[0-9a-f]{64}`)

// A new token is shown once; afterwards only its key ending is.
func TestTokenCreatedOnce(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "alice", "GET", "/settings/tokens/new", nil, nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), `name="action" value="comment"`) {
		t.Fatalf("form %d", rec.Code)
	}
	form := url.Values{"name": {"laptop"}, "kind": {"mcp"}, "access": {"actions"}, "action": {"comment", "edit"},
		"engs": {"selected"}, "eng": {"acme"}, "expires": {"30"}}
	rec := e.do(t, "alice", "POST", "/settings/tokens/new", form, nil)
	if rec.Code != 200 {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	tok := secretRe.FindString(rec.Body.String())
	if tok == "" {
		t.Fatalf("secret not shown:\n%s", rec.Body.String())
	}
	tokens := auth.NewTokens(e.srv.Store.DB())
	u, info, ok := tokens.Verify(tok, db.TokenMCP)
	if !ok || u.Username != "alice" || info.Name != "laptop" || !slices.Equal(info.Scopes, []string{"edit", "comment"}) ||
		!slices.Equal(info.Engagements, []string{"acme"}) {
		t.Fatalf("token %+v %v", info, ok)
	}
	exp, _ := time.Parse(time.RFC3339, info.Expires)
	if d := time.Until(exp); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("expires %s", info.Expires)
	}
	b := e.do(t, "alice", "GET", "/settings", nil, nil).Body.String()
	if strings.Contains(b, tok) || secretRe.MatchString(b) {
		t.Fatal("secret shown again")
	}
	if !strings.Contains(b, "…"+tok[len(tok)-4:]) || !strings.Contains(b, "laptop") {
		t.Fatalf("token not listed by its ending:\n%s", b)
	}
	// read only, every engagement, never expires
	rec = e.do(t, "alice", "POST", "/settings/tokens/new", url.Values{"name": {"ro"}, "kind": {"git"}, "access": {"read"}, "engs": {"all"}, "expires": {"never"}}, nil)
	_, info, ok = tokens.Verify(secretRe.FindString(rec.Body.String()), db.TokenGit)
	if !ok || !info.ReadOnly() || info.Restricted() || info.Expires != "" {
		t.Fatalf("read-only token %+v", info)
	}
	// an engagement the user can't see is refused
	dora, _ := e.srv.Auth.Lookup("dora")
	e.srv.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, store.AuthorOf(dora))
	for _, f := range []url.Values{
		{"name": {"x"}, "kind": {"mcp"}, "access": {"read"}, "engs": {"selected"}, "eng": {"beta"}, "expires": {"30"}},
		{"name": {"x"}, "kind": {"mcp"}, "access": {"actions"}, "engs": {"all"}, "expires": {"30"}},
		{"name": {"x"}, "kind": {"ssh"}, "access": {"read"}, "engs": {"all"}, "expires": {"30"}},
		{"name": {""}, "kind": {"mcp"}, "access": {"read"}, "engs": {"all"}, "expires": {"30"}},
	} {
		if rec := e.do(t, "alice", "POST", "/settings/tokens/new", f, nil); rec.Code != http.StatusBadRequest || secretRe.MatchString(rec.Body.String()) {
			t.Fatalf("%v: %d", f, rec.Code)
		}
	}
	// revoke: own tokens only
	if rec := e.do(t, "bob", "POST", "/settings/tokens/"+strconv.FormatInt(info.ID, 10)+"/revoke", url.Values{}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("revoke someone else's: %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/settings/tokens/"+strconv.FormatInt(info.ID, 10)+"/revoke", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if l := tokens.ListFor("alice"); len(l) != 1 {
		t.Fatalf("tokens left %d", len(l))
	}
}

// Personal keys are stored encrypted and shown only by their ending.
func TestConnectionsMasked(t *testing.T) {
	e := setup(t)
	const key = "ATATT3xFfGF0-personal-key-9k2Q"
	if rec := e.do(t, "alice", "POST", "/settings/connections", url.Values{"service": {"jira"}, "key": {key}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("add %d", rec.Code)
	}
	enc, ok, _ := e.srv.Store.DB().Connection("alice", "jira")
	if !ok || strings.Contains(enc, key) || strings.Contains(enc, "9k2Q") {
		t.Fatalf("stored %q", enc)
	}
	box, err := e.srv.secrets()
	if err != nil {
		t.Fatal(err)
	}
	if plain, _ := box.Decrypt(enc); plain != key {
		t.Fatalf("decrypted %q", plain)
	}
	b := e.do(t, "alice", "GET", "/settings", nil, nil).Body.String()
	if strings.Contains(b, key) || !strings.Contains(b, "…9k2Q") {
		t.Fatalf("connections:\n%s", b)
	}
	if strings.Contains(e.do(t, "bob", "GET", "/settings", nil, nil).Body.String(), "…9k2Q") {
		t.Fatal("bob sees alice's key")
	}
	if rec := e.do(t, "alice", "POST", "/settings/connections", url.Values{"service": {"github"}, "key": {"x"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown service %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/settings/connections/jira/remove", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("remove %d", rec.Code)
	}
	if _, ok, _ := e.srv.Store.DB().Connection("alice", "jira"); ok {
		t.Fatal("key not removed")
	}
}

func TestNotificationPrefs(t *testing.T) {
	e := setup(t)
	c := e.srv.conf() // the email column needs mail settings
	c.SMTP = config.SMTPConfig{Host: "mail.example", Port: 25, From: "yars@example.com"}
	e.srv.setConfig(c)
	rec := e.do(t, "alice", "POST", "/settings/notifications", url.Values{"n": {"returned.app", "returned.email", "review.app", "bogus.app", "review.fax"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d", rec.Code)
	}
	p, _ := e.srv.Store.DB().NotifyPrefs("alice")
	if len(p) != 2 || !slices.Equal(p["returned"], []string{"app", "email"}) || !slices.Equal(p["review"], []string{"app"}) {
		t.Fatalf("prefs %v", p)
	}
	b := e.do(t, "alice", "GET", "/settings", nil, nil).Body.String()
	if !strings.Contains(b, `name="n" value="returned.email" checked`) || strings.Contains(b, `name="n" value="review.email" checked`) {
		t.Fatal("prefs not shown")
	}
	// saving again replaces the choice
	e.do(t, "alice", "POST", "/settings/notifications", url.Values{"n": {"approved.app"}}, nil)
	if p, _ := e.srv.Store.DB().NotifyPrefs("alice"); len(p) != 1 || p["approved"] == nil {
		t.Fatalf("prefs %v", p)
	}
}

// The new pages use the design system's classes only, and every table has
// column headers.
func TestAccountPagesStyled(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/settings", "/settings/tokens/new", "/admin/users", "/admin/engagements?team=acme", "/admin/ai",
		"/admin/system", "/admin/health", "/admin/activity"} {
		b := e.do(t, "dora", "GET", p, nil, nil).Body.String()
		if strings.Contains(b, ` style="`) || strings.Contains(b, "<style") {
			t.Errorf("%s: inline style", p)
		}
		if strings.Count(b, "<table") != strings.Count(b, "<thead>") {
			t.Errorf("%s: a table without column headers", p)
		}
	}
}

// The theme can also be chosen on the settings page, "system" included.
func TestSettingsTheme(t *testing.T) {
	e := setup(t)
	e.do(t, "alice", "POST", "/settings/theme", url.Values{"theme": {"dark"}}, nil)
	if rec := e.do(t, "alice", "POST", "/settings/theme", url.Values{"theme": {"system"}}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("system %d", rec.Code)
	}
	if u, _ := e.srv.Auth.Lookup("alice"); u.Theme != "" {
		t.Fatalf("theme %q", u.Theme)
	}
}
