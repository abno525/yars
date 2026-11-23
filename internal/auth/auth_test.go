package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
)

func newDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func newAuth(t *testing.T) (*Auth, *db.DB) {
	t.Helper()
	h, err := HashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	d := newDB(t)
	if err := d.AddUser(config.User{Username: "alice", Role: "pentester", PasswordHash: h}); err != nil {
		t.Fatal(err)
	}
	return New(d), d
}

// The session cookie is Secure when the site is served over HTTPS; it is
// always HttpOnly and SameSite=Lax, and clearing it matches.
func TestCookieSecureFlag(t *testing.T) {
	for _, secure := range []bool{false, true} {
		a := &Auth{Secure: secure}
		rec := httptest.NewRecorder()
		a.SetCookie(rec, "tok")
		a.ClearCookie(rec)
		cs := rec.Result().Cookies()
		if len(cs) != 2 {
			t.Fatalf("cookies %v", cs)
		}
		for _, c := range cs {
			if c.Name != CookieName || c.Secure != secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
				t.Errorf("secure=%v: cookie %+v", secure, c)
			}
		}
		if cs[0].Value != "tok" || cs[0].MaxAge <= 0 || cs[1].MaxAge >= 0 {
			t.Errorf("set %+v, clear %+v", cs[0], cs[1])
		}
	}
}

func TestLoginOK(t *testing.T) {
	a, _ := newAuth(t)
	tok, ok := a.Login("alice", "secret")
	if !ok || len(tok) != 64 {
		t.Fatalf("ok=%v tok=%q", ok, tok)
	}
}

func TestLoginBadPassword(t *testing.T) {
	a, _ := newAuth(t)
	if _, ok := a.Login("alice", "wrong"); ok {
		t.Fatal("bad password accepted")
	}
	if _, ok := a.Login("mallory", "secret"); ok {
		t.Fatal("unknown user accepted")
	}
}

func TestRequireRedirects(t *testing.T) {
	a, _ := newAuth(t)
	h := a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler reached") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("code=%d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func get(h http.Handler, tok string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRequirePassesUserInContext(t *testing.T) {
	a, _ := newAuth(t)
	tok, _ := a.Login("alice", "secret")
	var got config.User
	h := a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = UserFrom(r.Context()) }))
	get(h, tok)
	if got.Username != "alice" || got.Role != "pentester" {
		t.Fatalf("got %+v", got)
	}
	a.Logout(tok)
	if get(h, tok).Code != http.StatusSeeOther {
		t.Fatal("session survived logout")
	}
}

// Sessions live in the database: a restarted server (a new Auth on the same
// database) keeps everyone logged in, and only token hashes are stored.
func TestSessionsSurviveRestart(t *testing.T) {
	a, d := newAuth(t)
	tok, _ := a.Login("alice", "secret")
	restarted := New(d)
	ok := false
	h := restarted.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ok = true }))
	get(h, tok)
	if !ok {
		t.Fatal("session lost on restart")
	}
	var n int
	d.QueryRow("SELECT count(*) FROM sessions WHERE hash = ?", tok).Scan(&n)
	if n != 0 {
		t.Fatal("plain session token stored")
	}
}

// Accounts are read from the database on every request, so a role change or
// a deleted account takes effect without restarting the server.
func TestAccountChangesApplyAtOnce(t *testing.T) {
	a, d := newAuth(t)
	tok, _ := a.Login("alice", "secret")
	d.SetRole("alice", "director")
	var got config.User
	h := a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = UserFrom(r.Context()) }))
	get(h, tok)
	if got.Role != "director" {
		t.Fatalf("role %q", got.Role)
	}
	d.DeleteUser("alice")
	if get(h, tok).Code != http.StatusSeeOther {
		t.Fatal("deleted account still logged in")
	}
	if _, ok := a.Check("alice", "secret"); ok {
		t.Fatal("deleted account passes Check")
	}
	if len(a.Users()) != 0 {
		t.Fatal("Users lists a deleted account")
	}
}

// A disabled account can't log in, and its open sessions stop working.
func TestDisabledAccount(t *testing.T) {
	a, d := newAuth(t)
	tok, _ := a.Login("alice", "secret")
	h := a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d.SetDisabled("alice", true)
	if get(h, tok).Code != http.StatusSeeOther {
		t.Fatal("disabled account still logged in")
	}
	if _, ok := a.Login("alice", "secret"); ok {
		t.Fatal("disabled account logged in")
	}
	if _, ok := a.Check("alice", "secret"); ok {
		t.Fatal("disabled account passes Check")
	}
	if _, ok := a.Lookup("alice"); ok {
		t.Fatal("Lookup returns a disabled account")
	}
	d.SetDisabled("alice", false)
	if _, ok := a.Login("alice", "secret"); !ok {
		t.Fatal("re-enabled account can't log in")
	}
}

func TestLoginAudited(t *testing.T) {
	a, d := newAuth(t)
	a.Login("alice", "secret")
	a.Login("alice", "nope")
	a.Login("mallory", "x")
	l, _ := d.AuditLog(10)
	if len(l) != 3 || l[2].Action != "login" || l[2].Actor != "alice" || l[1].Action != "login.fail" || l[0].Target != "mallory" {
		t.Fatalf("audit %+v", l)
	}
}

// Failed logins are filed under one actor with the typed name as target,
// and repeats of a name within the hour make one row with a count, so typed
// names can't flood the log or the activity page's actor list.
func TestLoginFailAggregated(t *testing.T) {
	a, d := newAuth(t)
	for i := 0; i < 3; i++ {
		a.Login("mallory", "x")
	}
	a.Login("alice", "nope")
	l, _ := d.AuditLog(10)
	if len(l) != 2 {
		t.Fatalf("audit %+v", l)
	}
	if l[0].Actor != db.FailedLoginActor || l[0].Target != "alice" || l[0].Detail != "1 attempt" {
		t.Fatalf("alice row %+v", l[0])
	}
	if l[1].Actor != db.FailedLoginActor || l[1].Target != "mallory" || l[1].Detail != "3 attempts" {
		t.Fatalf("mallory row %+v", l[1])
	}
	if actors, _ := d.AuditActors(); len(actors) != 1 || actors[0] != db.FailedLoginActor {
		t.Fatalf("actors %v", actors)
	}
}
