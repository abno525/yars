package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// A deleted account's name is not given out again on Admin › Users: the
// form comes back with the reason, and no account is made.
func TestAdminUsersDeletedNameRefused(t *testing.T) {
	e := setup(t)
	e.addUser(t, config.User{Username: "pen9", Role: "pentester"})
	if err := e.srv.Store.DB().DeleteUser("pen9"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pen9", "Pen9"} {
		rec := e.do(t, "dora", "POST", "/admin/users", url.Values{"username": {name}, "role": {"pentester"}}, nil)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "user pen9 was deleted: the name stays taken") {
			t.Fatalf("add %s: %d\n%s", name, rec.Code, rec.Body.String())
		}
		if _, ok, _ := e.srv.Store.DB().User(name); ok {
			t.Fatalf("%s was made", name)
		}
	}
}

// The first account cannot take a deleted account's name either: /setup
// shows the form again with the reason.
func TestSetupDeletedNameRefused(t *testing.T) {
	e := fresh(t)
	d := e.srv.Store.DB()
	if err := d.AddUser(config.User{Username: "dir1", Role: "director", IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteUser("dir1"); err != nil {
		t.Fatal(err)
	}
	rec := e.do(t, "", "POST", "/setup", first(setupCode), nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `<div class="alert" role="alert">user dir1 was deleted: the name stays taken</div>`) {
		t.Fatalf("setup with a deleted name: %d\n%s", rec.Code, rec.Body.String())
	}
	if n, _ := d.UserCount(); n != 0 {
		t.Fatalf("%d accounts", n)
	}
	f := first(setupCode)
	f.Set("username", "dir2")
	if rec := e.do(t, "", "POST", "/setup", f, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("setup with a new name: %d", rec.Code)
	}
}
