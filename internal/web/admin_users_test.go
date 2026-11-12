package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"yars/internal/config"
)

// Every admin page and action is for admins only (the flag, not the role).
func TestAdminPagesAdminOnly(t *testing.T) {
	e := setup(t)
	e.addUser(t, config.User{Username: "dir2", Role: "director"})
	pages := []string{"/admin/users", "/admin/ai", "/admin/system", "/admin/activity"}
	for _, p := range pages {
		for _, u := range []string{"alice", "dir2"} {
			if rec := e.do(t, u, "GET", p, nil, nil); rec.Code != http.StatusForbidden {
				t.Errorf("GET %s by %s: %d", p, u, rec.Code)
			}
		}
		if rec := e.do(t, "dora", "GET", p, nil, nil); rec.Code != 200 {
			t.Errorf("GET %s by admin: %d", p, rec.Code)
		}
	}
	posts := []string{"/admin/users", "/admin/users/bob/role", "/admin/users/bob/admin", "/admin/users/bob/disabled", "/admin/users/bob/reset",
		"/admin/ai", "/admin/ai/test",
		"/admin/system/sync", "/admin/system/reindex", "/admin/system/migrate", "/admin/system/check", "/admin/system/backup", "/admin/activity/sessions/1/revoke", "/admin/activity/tokens/1/revoke"}
	for _, p := range posts {
		if rec := e.do(t, "alice", "POST", p, url.Values{}, nil); rec.Code != http.StatusForbidden {
			t.Errorf("POST %s by alice: %d", p, rec.Code)
		}
	}
	// the admin pages have one active nav item: Admin
	b := e.do(t, "dora", "GET", "/admin/users", nil, nil).Body.String()
	if !strings.Contains(b, `<a class="on" href="/admin">`) || strings.Count(b, `class="on"`) != 1 || strings.Contains(b, `class="who on"`) {
		t.Fatal("admin page nav")
	}
}

var tempPwRe = regexp.MustCompile(`id="temp-pw">([^<]+)<`)

func TestAdminUsers(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/admin/users", nil, nil).Body.String()
	for _, want := range []string{"<th>User</th>", "<th class=\"c-role\">Role</th>", "alice", `name="role"`, "Reset pass"} {
		if !strings.Contains(b, want) {
			t.Fatalf("users page lacks %q:\n%s", want, b)
		}
	}
	// add: shown once with its temporary password
	rec := e.do(t, "dora", "POST", "/admin/users", url.Values{"username": {"pen3"}, "email": {"pen3@x.test"}, "role": {"pentester"}}, nil)
	if rec.Code != 200 {
		t.Fatalf("add %d %s", rec.Code, rec.Body.String())
	}
	m := tempPwRe.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatalf("no temporary password:\n%s", rec.Body.String())
	}
	// it logs in (to set a new password: D26)
	if _, ok := e.srv.Auth.Login("pen3", m[1]); !ok {
		t.Fatal("temporary password does not work")
	}
	if rec := e.do(t, "dora", "POST", "/admin/users", url.Values{"username": {"pen3"}, "role": {"pentester"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/users", url.Values{"username": {"bad name"}, "role": {"pentester"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad name %d", rec.Code)
	}
	// role, admin, disabled
	if rec := e.do(t, "dora", "POST", "/admin/users/pen3/role", url.Values{"role": {"reviewer"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("role %d", rec.Code)
	}
	e.do(t, "dora", "POST", "/admin/users/pen3/admin", url.Values{"on": {"1"}}, nil)
	u, _ := e.srv.Auth.Lookup("pen3")
	if u.Role != "reviewer" || !u.IsAdmin {
		t.Fatalf("pen3 %+v", u)
	}
	if rec := e.do(t, "dora", "POST", "/admin/users/alice/disabled", url.Values{"on": {"1"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("disable %d", rec.Code)
	}
	if rec := e.do(t, "alice", "GET", "/", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatal("disabled user still signed in")
	}
	if b := e.do(t, "dora", "GET", "/admin/users", nil, nil).Body.String(); !strings.Contains(b, `aria-label="Disabled alice" aria-pressed="true"`) {
		t.Fatal("disabled state not shown")
	}
	l, _ := e.srv.Store.DB().AuditLog(10)
	var actions []string
	for _, a := range l {
		actions = append(actions, a.Action)
	}
	if !strings.Contains(strings.Join(actions, " "), "user.disable") || !strings.Contains(strings.Join(actions, " "), "user.add") {
		t.Fatalf("audit %v", actions)
	}
	e.do(t, "dora", "POST", "/admin/users/alice/disabled", url.Values{}, nil)
	if _, ok := e.srv.Auth.Lookup("alice"); !ok {
		t.Fatal("alice not enabled again")
	}
	// reset: a new temporary password, shown once
	rec = e.do(t, "dora", "POST", "/admin/users/bob/reset", url.Values{}, nil)
	m = tempPwRe.FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || m == nil {
		t.Fatalf("reset %d", rec.Code)
	}
	if _, ok := e.srv.Auth.Login("bob", m[1]); !ok {
		t.Fatal("reset password does not work")
	}
	// an admin can't lock themselves out
	for _, p := range []string{"/admin/users/dora/disabled", "/admin/users/dora/admin"} {
		f := url.Values{}
		if strings.HasSuffix(p, "disabled") {
			f.Set("on", "1")
		}
		if rec := e.do(t, "dora", "POST", p, f, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s on self: %d", p, rec.Code)
		}
	}
	if rec := e.do(t, "dora", "POST", "/admin/users/ghost/role", url.Values{"role": {"reviewer"}}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown user %d", rec.Code)
	}
}

// Admin activity: disabling and enabling an account carry no "on"/"off"
// detail, which read backwards next to the action.
func TestAuditDisableEnableDetail(t *testing.T) {
	e := setup(t)
	e.do(t, "dora", "POST", "/admin/users/alice/disabled", url.Values{"on": {"1"}}, nil)
	e.do(t, "dora", "POST", "/admin/users/alice/disabled", url.Values{}, nil)
	l, _ := e.srv.Store.DB().AuditLog(10)
	seen := map[string]bool{}
	for _, a := range l {
		if a.Action == "user.disable" || a.Action == "user.enable" {
			seen[a.Action] = true
			if a.Detail != "" {
				t.Errorf("%s detail %q", a.Action, a.Detail)
			}
		}
	}
	if !seen["user.disable"] || !seen["user.enable"] {
		t.Fatalf("audit %+v", l)
	}
	// a row stored the old way reads right on the page too
	e.srv.Store.DB().Audit("dora", "user.disable", "bob", "on")
	b := e.do(t, "dora", "GET", "/admin/activity", nil, nil).Body.String()
	if row := between(b, ">user.disable<", "</tr>"); strings.Contains(row, ">on<") || strings.Contains(row, ">off<") {
		t.Fatalf("activity row: %s", row)
	}
}
