package db

import (
	"errors"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// The last enabled admin keeps the flag, stays enabled and is not deleted:
// each of the three writes answers ErrLastAdmin and changes nothing. With
// another enabled admin each works; a disabled admin is no "other".
func TestLastAdminStays(t *testing.T) {
	writes := map[string]func(*DB, string) error{
		"admin off": func(d *DB, name string) error { return d.SetAdmin(name, false) },
		"disable":   func(d *DB, name string) error { return d.SetDisabled(name, true) },
		"delete":    func(d *DB, name string) error { return d.DeleteUser(name) },
	}
	for what, write := range writes {
		t.Run(what, func(t *testing.T) {
			d, _ := open(t)
			for _, u := range []config.User{
				{Username: "ann", Role: "director", IsAdmin: true},
				{Username: "bea", Role: "director", IsAdmin: true, Disabled: true},
				{Username: "pen", Role: "pentester"},
			} {
				if err := d.AddUser(u); err != nil {
					t.Fatal(err)
				}
			}
			d.CreateSession("s-ann", "ann")
			seq, _ := d.Seq()
			// bea is disabled: ann is the last admin who can sign in
			if err := write(d, "ann"); !errors.Is(err, ErrLastAdmin) {
				t.Fatalf("%s on the last admin: %v", what, err)
			}
			if u, ok, _ := d.User("ann"); !ok || !u.IsAdmin || u.Disabled {
				t.Fatalf("ann after the refusal: %+v %v", u, ok)
			}
			if _, ok, _ := d.SessionUser("s-ann"); !ok {
				t.Fatal("the refusal ended ann's session")
			}
			if again, _ := d.Seq(); again != seq {
				t.Fatalf("the refusal wrote: seq %d, was %d", again, seq)
			}
			if count(t, d, "deleted_users") != 0 {
				t.Fatal("the refusal remembered a deleted name")
			}
			// an account that is no admin, and an admin who is disabled already,
			// are not the last admin
			if err := write(d, "pen"); err != nil {
				t.Fatalf("%s on a pentester: %v", what, err)
			}
			if err := write(d, "bea"); err != nil {
				t.Fatalf("%s on a disabled admin: %v", what, err)
			}
			// with a second enabled admin, ann is not the last
			if err := d.AddUser(config.User{Username: "cy", Role: "director", IsAdmin: true}); err != nil {
				t.Fatal(err)
			}
			if err := write(d, "ann"); err != nil {
				t.Fatalf("%s with another admin: %v", what, err)
			}
			// now cy is
			if err := write(d, "cy"); !errors.Is(err, ErrLastAdmin) {
				t.Fatalf("%s on the admin left: %v", what, err)
			}
		})
	}
}

// Turning the flag on, enabling, and a data folder that has no admin at all
// are never refused; an unknown name keeps its own answer.
func TestLastAdminRuleLeavesTheRest(t *testing.T) {
	d, _ := open(t)
	for _, u := range []config.User{{Username: "pen", Role: "pentester"}, {Username: "rev", Role: "reviewer"}} {
		if err := d.AddUser(u); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.SetDisabled("pen", true); err != nil {
		t.Fatal(err)
	}
	if err := d.SetDisabled("pen", false); err != nil {
		t.Fatal(err)
	}
	if err := d.SetAdmin("pen", false); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteUser("rev"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetAdmin("pen", true); err != nil {
		t.Fatal(err)
	}
	for what, err := range map[string]error{"admin off": d.SetAdmin("ghost", false), "disable": d.SetDisabled("ghost", true), "delete": d.DeleteUser("ghost")} {
		if err == nil || errors.Is(err, ErrLastAdmin) || err.Error() != "no user ghost" {
			t.Errorf("%s on an unknown name: %v", what, err)
		}
	}
}
