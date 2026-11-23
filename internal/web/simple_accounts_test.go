package web

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"yars/internal/db"
)

// Admin › Users of the simple workflow: no Role column, no role select in a
// row, no Role choice in the Add user form (username, email, admin and
// password).
func TestSimpleAdminUsersNoRole(t *testing.T) {
	e := setupSimple(t)
	b := e.do(t, "anna", "GET", "/admin/users", nil, nil).Body.String()
	tbl := between(b, `<table class="table stable usertable"`, "</table>")
	if !strings.Contains(tbl, `<thead><tr><th>User</th><th class="c-flag">Admin</th><th class="c-flag">Disabled</th>`) {
		t.Fatalf("users table head:\n%s", tbl)
	}
	for _, no := range []string{"c-role", ">Role<", `name="role"`, "Role of ", ">director<"} {
		if strings.Contains(b, no) {
			t.Errorf("users page has %q", no)
		}
	}
	form := between(b, `<form class="panel compact sidecol" method="post" action="/admin/users">`, "</form>")
	for _, want := range []string{`name="username"`, `name="email"`, `name="admin"`, `name="password"`} {
		if !strings.Contains(form, want) {
			t.Errorf("add form lacks %q", want)
		}
	}
	if strings.Contains(form, "<legend>Role</legend>") || strings.Contains(form, `type="radio"`) {
		t.Fatalf("add form has a role:\n%s", form)
	}
	// the rows keep their other cells: the admin flag and Reset pass
	if !strings.Contains(tbl, `aria-label="Admin ben"`) || !strings.Contains(tbl, "Reset pass") {
		t.Fatalf("rows:\n%s", tbl)
	}
}

// Every account added in the simple workflow is a director; a posted role
// is ignored, and the audit names the admin flag only.
func TestSimpleAddUserIsDirector(t *testing.T) {
	e := setupSimple(t)
	for _, f := range []url.Values{
		{"username": {"cleo"}, "email": {"cleo@x.test"}, "role": {"pentester"}, "admin": {"1"}},
		{"username": {"dan"}, "role": {"bogus"}},
		{"username": {"eve"}},
	} {
		rec := e.do(t, "anna", "POST", "/admin/users", f, nil)
		if rec.Code != 200 || tempPwRe.FindStringSubmatch(rec.Body.String()) == nil {
			t.Fatalf("add %v: %d", f, rec.Code)
		}
	}
	for name, admin := range map[string]bool{"cleo": true, "dan": false, "eve": false} {
		u, ok := e.srv.Auth.Lookup(name)
		if !ok || u.Role != "director" || u.IsAdmin != admin {
			t.Errorf("%s: %+v", name, u)
		}
	}
	l, _ := e.srv.Store.DB().AuditLog(10)
	got := map[string]string{}
	for _, a := range l {
		if a.Action == "user.add" {
			got[a.Target] = a.Detail
		}
	}
	if len(got) != 3 || got["cleo"] != "admin" || got["dan"] != "" || got["eve"] != "" {
		t.Fatalf("audit %v", got)
	}
	// the other checks stay
	if rec := e.do(t, "anna", "POST", "/admin/users", url.Values{"username": {"bad name"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad name %d", rec.Code)
	}
	if rec := e.do(t, "anna", "POST", "/admin/users", url.Values{"username": {"cleo"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate %d", rec.Code)
	}
}

// The role endpoint answers 400 in the simple workflow and changes nothing.
func TestSimpleRoleEndpointRefused(t *testing.T) {
	e := setupSimple(t)
	rec := e.do(t, "anna", "POST", "/admin/users/ben/role", url.Values{"role": {"pentester"}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "The simple workflow has no roles") {
		t.Fatalf("role %d", rec.Code)
	}
	if u, _ := e.srv.Auth.Lookup("ben"); u.Role != "director" {
		t.Fatalf("ben %+v", u)
	}
	l, _ := e.srv.Store.DB().AuditLog(10)
	for _, a := range l {
		if a.Action == "user.role" {
			t.Fatalf("audited %+v", a)
		}
	}
	// admins only, as before
	if rec := e.do(t, "ben", "POST", "/admin/users/anna/role", url.Values{"role": {"pentester"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("ben: %d", rec.Code)
	}
}

// Settings › Account: an Access field instead of Roles: the admin tag, or a
// muted dash.
func TestSimpleSettingsAccess(t *testing.T) {
	e := setupSimple(t)
	for user, want := range map[string]string{
		"anna": `<span class="flabel">Access</span><span class="fvalue tags"><span class="tag adminflag">admin</span></span>`,
		"ben":  `<span class="flabel">Access</span><span class="fvalue tags"><span class="muted">—</span></span>`,
	} {
		b := e.do(t, user, "GET", "/settings", nil, nil).Body.String()
		acct := between(b, `id="account"`, "</form>")
		if !strings.Contains(acct, want) {
			t.Errorf("%s account:\n%s", user, acct)
		}
		if strings.Contains(acct, ">Roles<") || strings.Contains(acct, "tag role") || strings.Contains(acct, "director") {
			t.Errorf("%s: a role shown:\n%s", user, acct)
		}
	}
	// the standard workflow keeps Roles
	std := setup(t)
	if b := std.do(t, "dora", "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, `<span class="flabel">Roles</span><span class="fvalue tags"><span class="tag role">director</span><span class="tag adminflag">admin</span></span>`) {
		t.Fatal("standard Roles field")
	}
}

// A token of the simple workflow has no Assign reviewers scope: the form
// does not list it and a posted one is not taken.
func TestSimpleTokenScopes(t *testing.T) {
	e := setupSimple(t)
	b := e.do(t, "ben", "GET", "/settings/tokens/new", nil, nil).Body.String()
	if strings.Contains(b, `value="reviewers"`) || strings.Contains(b, "Assign reviewers") {
		t.Fatal("the reviewers scope is listed")
	}
	for _, a := range db.TokenActions {
		if a != "reviewers" && !strings.Contains(b, `name="action" value="`+a+`"`) {
			t.Errorf("%s not listed", a)
		}
	}
	f := url.Values{"name": {"bot"}, "kind": {"mcp"}, "access": {"actions"}, "engs": {"all"}, "expires": {"30"}, "action": {"reviewers"}}
	if rec := e.do(t, "ben", "POST", "/settings/tokens/new", f, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Pick at least one action") {
		t.Fatalf("reviewers only: %d", rec.Code)
	}
	f["action"] = []string{"reviewers", "status"}
	if rec := e.do(t, "ben", "POST", "/settings/tokens/new", f, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("create %d", rec.Code)
	}
	l := e.srv.Tokens.ListFor("ben")
	if len(l) != 1 || !slices.Equal(l[0].Scopes, []string{"status"}) {
		t.Fatalf("tokens %+v", l)
	}
	// the standard workflow keeps it
	std := setup(t)
	if b := std.do(t, "alice", "GET", "/settings/tokens/new", nil, nil).Body.String(); !strings.Contains(b, `name="action" value="reviewers"`) {
		t.Fatal("standard scopes")
	}
}
