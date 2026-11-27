package db

import (
	"errors"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// A deleted account's name stays taken: the rows without a foreign key
// (sign-offs, chat, dismissals, the author of findings) would belong to
// whoever got the name next.
func TestDeletedUsernameStaysTaken(t *testing.T) {
	d, _ := open(t)
	if err := d.AddUser(config.User{Username: "bob", Role: "reviewer"}); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteUser("bob"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bob", "Bob", "BOB"} {
		err := d.AddUser(config.User{Username: name, Role: "pentester", Email: name + "@x"})
		if !errors.Is(err, ErrUserExists) || !strings.Contains(err.Error(), "was deleted: the name stays taken") {
			t.Fatalf("AddUser %s after bob was deleted: %v", name, err)
		}
	}
	if us, _ := d.Users(); len(us) != 0 {
		t.Fatalf("accounts %+v", us)
	}
	if err := d.AddUser(config.User{Username: "bobby", Role: "pentester"}); err != nil {
		t.Fatalf("another name: %v", err)
	}
	// a delete of an account that is not there remembers nothing
	if err := d.DeleteUser("carol"); err == nil {
		t.Fatal("deleted an account that is not there")
	}
	if err := d.AddUser(config.User{Username: "carol", Role: "pentester"}); err != nil {
		t.Fatalf("carol: %v", err)
	}
}

// The first account is made the same way: after every account was deleted,
// an old name is refused and a new one is taken.
func TestFirstUserNotADeletedName(t *testing.T) {
	d, _ := open(t)
	if err := d.AddFirstUser(config.User{Username: "dora", Role: "director", IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteUser("dora"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"dora", "Dora"} {
		if err := d.AddFirstUser(config.User{Username: name, Role: "director", IsAdmin: true}); !errors.Is(err, ErrUserExists) {
			t.Fatalf("AddFirstUser %s: %v", name, err)
		}
	}
	if n, _ := d.UserCount(); n != 0 {
		t.Fatalf("%d accounts", n)
	}
	if err := d.AddFirstUser(config.User{Username: "erin", Role: "director", IsAdmin: true}); err != nil {
		t.Fatalf("a new name: %v", err)
	}
	if err := d.AddFirstUser(config.User{Username: "fay", Role: "director"}); !errors.Is(err, ErrNotFirst) {
		t.Fatalf("a second first account: %v", err)
	}
}

// A database from before the table opens, gets it, and remembers a delete
// made after that. Opening a current database again writes nothing.
func TestDeletedUsernamesMigration(t *testing.T) {
	p := openAtVersion(t, legacySchema)
	raw := rawDB(t, p)
	if _, err := raw.Exec("INSERT INTO users(username, email, role, created) VALUES ('bob', 'b@x', 'reviewer', 'x')"); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if count(t, d, "deleted_users") != 0 {
		t.Fatal("names in a new table")
	}
	if err := d.DeleteUser("bob"); err != nil {
		t.Fatal(err)
	}
	seq, _ := d.Seq()
	d.Close()
	d, err = Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if again, _ := d.Seq(); again != seq || len(snapshots(t, p)) != 1 {
		t.Fatalf("the second open wrote: seq %d, was %d; snapshots %v", again, seq, snapshots(t, p))
	}
	if err := d.AddUser(config.User{Username: "bob", Role: "reviewer"}); !errors.Is(err, ErrUserExists) {
		t.Fatalf("bob after a reopen: %v", err)
	}
}
