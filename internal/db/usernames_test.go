package db

import (
	"errors"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// Two usernames that differ only in the case of ASCII letters are one name
// to a person reading it: the second is refused, whatever its email.
func TestUsernamesDifferingInCaseRefused(t *testing.T) {
	d, _ := open(t)
	if err := d.AddUser(config.User{Username: "alice", Role: "pentester", Email: "a@x"}); err != nil {
		t.Fatal(err)
	}
	for _, u := range []config.User{
		{Username: "Alice", Role: "director", Email: "b@x"},
		{Username: "ALICE", Role: "pentester"},
	} {
		err := d.AddUser(u)
		if !errors.Is(err, ErrUserExists) || !strings.Contains(err.Error(), "already exists as alice") {
			t.Fatalf("AddUser %s: %v", u.Username, err)
		}
	}
	if err := d.AddUser(config.User{Username: "alice", Role: "pentester", Email: "c@x"}); !errors.Is(err, ErrUserExists) || err.Error() != "user alice already exists" {
		t.Fatalf("the same name again: %v", err)
	}
	if us, _ := d.Users(); len(us) != 1 {
		t.Fatalf("accounts %+v", us)
	}
	// other letters are not folded: these are two names
	if err := d.AddUser(config.User{Username: "älice", Role: "pentester", Email: "d@x"}); err != nil {
		t.Fatal(err)
	}
	if err := d.AddUser(config.User{Username: "Älice", Role: "pentester", Email: "e@x"}); err != nil {
		t.Fatal(err)
	}
	// the index holds the rule for a row written past AddUser
	if _, err := d.Exec("INSERT INTO users(username, email, role, created) VALUES ('ALICE', 'f@x', 'pentester', 'x')"); err == nil {
		t.Fatal("a raw insert of ALICE beside alice")
	}
	if cl, err := d.UsernameClashes(); err != nil || len(cl) != 0 {
		t.Fatalf("clashes %v %v", cl, err)
	}
}

// A database that already holds two such accounts opens, keeps both and
// lists them; a third is refused. One without such a pair gets the index.
func TestUsernamesMigration(t *testing.T) {
	p := openAtVersion(t, 24)
	raw := rawDB(t, p)
	if _, err := raw.Exec("INSERT INTO users(username, email, role, password_hash, created) VALUES ('alice', 'a@x', 'pentester', 'h1', 'x'), ('Alice', 'b@x', 'director', 'h2', 'x')"); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	d, err := Open(p)
	if err != nil {
		t.Fatalf("a database with alice and Alice: %v", err)
	}
	defer d.Close()
	for name, hash := range map[string]string{"alice": "h1", "Alice": "h2"} {
		if u, ok, err := d.User(name); err != nil || !ok || u.PasswordHash != hash {
			t.Fatalf("%s after the upgrade: %+v %v %v", name, u, ok, err)
		}
	}
	if cl, err := d.UsernameClashes(); err != nil || len(cl) != 1 || cl[0] != "Alice, alice" {
		t.Fatalf("clashes %v %v", cl, err)
	}
	if err := d.AddUser(config.User{Username: "ALICE", Role: "pentester", Email: "c@x"}); !errors.Is(err, ErrUserExists) {
		t.Fatalf("a third: %v", err)
	}

	p = openAtVersion(t, 24)
	raw = rawDB(t, p)
	if _, err := raw.Exec("INSERT INTO users(username, email, role, created) VALUES ('alice', 'a@x', 'pentester', 'x')"); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	d2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d2.Close()
	if _, err := d2.Exec("INSERT INTO users(username, email, role, created) VALUES ('Alice', 'b@x', 'pentester', 'x')"); err == nil {
		t.Fatal("an upgraded database without a clash has no index")
	}
}
