package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// D27: 5 failed logins lock the username for 15 minutes: the login page
// shows "Too many attempts" with a countdown in the alert box, even the
// right password is refused, git password auth too; it is written to the
// audit log and an admin can clear it from Admin › Users.
func TestLoginLockout(t *testing.T) {
	e := setup(t)
	try := func(pw string) *http.Response {
		return e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {pw}}, nil).Result()
	}
	for i := 0; i < 4; i++ {
		if res := try("wrong"); res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("failure %d: %d", i+1, res.StatusCode)
		}
	}
	rec := e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"wrong"}}, nil)
	b := rec.Body.String()
	if !regexp.MustCompile(`<div class="barealert" role="alert" data-lock-secs="(8\d\d|900)" data-lock-name="alice"><span>Too many attempts</span><span>Try again in <span class="mono" data-lock-left>1[45]:\d\d</span></span></div>`).MatchString(b) {
		t.Fatalf("5th failure:\n%s", b)
	}
	if !strings.Contains(b, `value="alice"`) || !strings.Contains(b, `<button class="btn primary barebtn" disabled>Log in</button>`) {
		t.Fatalf("form during the lockout:\n%s", b)
	}
	// the right password does not get through, nor git auth
	if res := try("pw"); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("right password while locked: %d", res.StatusCode)
	}
	if _, ok := e.srv.Auth.Check("alice", "pw"); ok {
		t.Fatal("git auth while locked")
	}
	// another name is not affected
	if res := e.do(t, "", "POST", "/login", url.Values{"username": {"bob"}, "password": {"pw"}}, nil).Result(); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("bob: %d", res.StatusCode)
	}
	if acts := e.do(t, "dora", "GET", "/admin/activity", nil, nil).Body.String(); !strings.Contains(acts, "login.lockout") {
		t.Fatal("no audit entry for the lockout")
	}
	// Admin › Users: Clear on alice's row only
	users := e.do(t, "dora", "GET", "/admin/users", nil, nil).Body.String()
	if strings.Count(users, `action="/admin/users/alice/unlock"`) != 1 || strings.Contains(users, `/admin/users/bob/unlock`) {
		t.Fatalf("users page:\n%s", users)
	}
	if rec := e.do(t, "alice", "POST", "/admin/users/alice/unlock", nil, nil); rec.Code != http.StatusForbidden && rec.Code != http.StatusNotFound {
		t.Fatalf("a non-admin cleared it: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/users/alice/unlock", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("clear %d", rec.Code)
	}
	if res := try("pw"); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("login after the clear: %d", res.StatusCode)
	}
	if acts := e.do(t, "dora", "GET", "/admin/activity", nil, nil).Body.String(); !strings.Contains(acts, "login.unlock") {
		t.Fatal("no audit entry for the clear")
	}
}

// A name without an account is locked out the same way: the alert proves
// nothing about whether an account exists.
func TestLockoutUnknownName(t *testing.T) {
	e := setup(t)
	var b string
	for i := 0; i < 5; i++ {
		b = e.do(t, "", "POST", "/login", url.Values{"username": {"nobody"}, "password": {"x"}}, nil).Body.String()
	}
	if !strings.Contains(b, "Too many attempts") {
		t.Fatalf("unknown name not locked:\n%s", b)
	}
}
