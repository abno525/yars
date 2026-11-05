package db

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"yars/internal/chat"
	"yars/internal/config"
)

func open(t *testing.T) (*DB, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".yars", "yars.db")
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, p
}

func TestOpenCreatesPrivateFileAndSchema(t *testing.T) {
	d, p := open(t)
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}
	var v int
	d.QueryRow("PRAGMA user_version").Scan(&v)
	if v != schemaVersion {
		t.Fatalf("version %d", v)
	}
	d.Close()
	d2, err := Open(p) // reopening an up-to-date database is a no-op
	if err != nil {
		t.Fatal(err)
	}
	d2.Close()
}

func TestSeqBumps(t *testing.T) {
	d, _ := open(t)
	s0, _ := d.Seq()
	if err := d.Tx(func(tx *Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if s1, _ := d.Seq(); s1 != s0+1 {
		t.Fatalf("seq %d -> %d", s0, s1)
	}
}

func TestUsers(t *testing.T) {
	d, _ := open(t)
	if err := d.AddUser(config.User{Username: "bob", Role: "reviewer", PasswordHash: "h1"}); err != nil {
		t.Fatal(err)
	}
	if err := d.AddUser(config.User{Username: "bob", Role: "reviewer"}); err == nil {
		t.Fatal("duplicate user added")
	}
	if err := d.AddUser(config.User{Username: "eve", Role: "admin"}); err == nil {
		t.Fatal("unknown role accepted")
	}
	d.AddUser(config.User{Username: "alice", Role: "pentester", Email: "a@x"})
	us, err := d.Users()
	if err != nil || len(us) != 2 || us[0].Username != "alice" || us[0].Email != "a@x" {
		t.Fatalf("users %+v %v", us, err)
	}
	if err := d.SetRole("bob", "director"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetPassword("bob", "h2"); err != nil {
		t.Fatal(err)
	}
	u, ok, _ := d.User("bob")
	if !ok || u.Role != "director" || u.PasswordHash != "h2" {
		t.Fatalf("bob %+v", u)
	}
	if err := d.SetRole("nobody", "director"); err == nil {
		t.Fatal("role set on unknown user")
	}
	if err := d.DeleteUser("bob"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := d.User("bob"); ok {
		t.Fatal("bob still there")
	}
}

func TestTokens(t *testing.T) {
	d, _ := open(t)
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	if err := d.AddToken("bob", "hash1"); err != nil {
		t.Fatal(err)
	}
	if err := d.AddToken("ghost", "hash2"); err == nil {
		t.Fatal("token for unknown user")
	}
	if u, ok, _ := d.TokenUser("hash1"); !ok || u != "bob" {
		t.Fatal("token lookup")
	}
	if ts, _ := d.Tokens(); len(ts) != 1 || ts[0].User != "bob" {
		t.Fatalf("list %+v", ts)
	}
	d.RevokeTokens("bob")
	if _, ok, _ := d.TokenUser("hash1"); ok {
		t.Fatal("revoked token works")
	}
	// deleting a user drops their tokens and sessions
	d.AddToken("bob", "hash3")
	d.CreateSession("sess", "bob")
	d.DeleteUser("bob")
	if _, ok, _ := d.TokenUser("hash3"); ok {
		t.Fatal("token outlived its user")
	}
	if _, ok, _ := d.SessionUser("sess"); ok {
		t.Fatal("session outlived its user")
	}
}

// A password reset (e.g. after a compromise) ends every existing session.
func TestSetPasswordEndsSessions(t *testing.T) {
	d, _ := open(t)
	d.AddUser(config.User{Username: "bob", Role: "reviewer", PasswordHash: "h1"})
	d.CreateSession("s1", "bob")
	if err := d.SetPassword("bob", "h2"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := d.SessionUser("s1"); ok {
		t.Fatal("session survived a password change")
	}
}

// IDs that ever had workflow state or chat are known, even after their
// folder is gone; a new engagement with an old name starts clean.
func TestKnownAndPurge(t *testing.T) {
	d, _ := open(t)
	if k, _ := d.Known("acme", "F-001"); k {
		t.Fatal("unknown id reported known")
	}
	d.Tx(func(tx *Tx) error {
		return tx.AddMessage("acme", "F-001", chat.Message{ID: "m1", User: "bob", Text: "x"})
	})
	if k, _ := d.Known("acme", "F-001"); !k {
		t.Fatal("id with chat not known")
	}
	d.Tx(func(tx *Tx) error { return tx.PutState("acme", "F-002", State{Status: "complete"}) })
	if err := d.Tx(func(tx *Tx) error { return tx.Purge("acme") }); err != nil {
		t.Fatal(err)
	}
	if k1, _ := d.Known("acme", "F-001"); k1 {
		t.Fatal("chat survived purge")
	}
	if k2, _ := d.Known("acme", "F-002"); k2 {
		t.Fatal("state survived purge")
	}
}

func TestSessionsExpireWhenIdle(t *testing.T) {
	d, _ := open(t)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	if err := d.CreateSession("s1", "bob"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(13 * 24 * time.Hour) // used within the window: refreshed
	if u, ok, _ := d.SessionUser("s1"); !ok || u != "bob" {
		t.Fatal("session lost early")
	}
	now = now.Add(13 * 24 * time.Hour) // 13 days after the last use: still valid
	if _, ok, _ := d.SessionUser("s1"); !ok {
		t.Fatal("last_seen not refreshed")
	}
	now = now.Add(SessionIdle + time.Minute)
	if _, ok, _ := d.SessionUser("s1"); ok {
		t.Fatal("idle session still valid")
	}
	d.CreateSession("s2", "bob")
	d.DeleteSession("s2")
	if _, ok, _ := d.SessionUser("s2"); ok {
		t.Fatal("deleted session valid")
	}
}
