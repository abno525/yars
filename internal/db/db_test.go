package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
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

// SchemaOf reads a database file's version without changing it; a missing
// file is an error, not a new database.
func TestSchemaOf(t *testing.T) {
	d, p := open(t)
	if _, err := d.Exec("PRAGMA user_version = 7"); err != nil {
		t.Fatal(err)
	}
	if v, err := SchemaOf(p); err != nil || v != 7 {
		t.Fatalf("SchemaOf %d %v", v, err)
	}
	missing := filepath.Join(t.TempDir(), "none.db")
	if _, err := SchemaOf(missing); err == nil {
		t.Fatal("SchemaOf of a missing file")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("SchemaOf created the file")
	}
}

// openAtVersion creates a database file at schema v (the first v migrations,
// their Go steps included), closes it and returns its path.
func openAtVersion(t *testing.T, v int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".yars", "yars.db")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for i, m := range migrations[0:v] {
		tx, err := raw.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(m); err != nil {
			t.Fatalf("migration %d: %v", i+1, err)
		}
		if fn := goMigrations[i]; fn != nil {
			if err := fn(tx); err != nil {
				t.Fatalf("migration %d: %v", i+1, err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := raw.Exec(fmt.Sprintf("PRAGMA user_version = %d", v)); err != nil {
		t.Fatal(err)
	}
	return p
}

// Opening an older database keeps a copy of it as it was, private.
func TestMigrateKeepsSnapshot(t *testing.T) {
	p := openAtVersion(t, schemaVersion-1)
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	snap := fmt.Sprintf("%s.before-v%d", p, schemaVersion-1)
	info, err := os.Stat(snap)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode %v", info.Mode().Perm())
	}
	if v, err := SchemaOf(snap); err != nil || v != schemaVersion-1 {
		t.Fatalf("snapshot schema %d %v", v, err)
	}
}

// Only the two newest snapshots are kept.
func TestMigrateKeepsTwoSnapshots(t *testing.T) {
	p := openAtVersion(t, schemaVersion-1)
	for _, v := range []int{3, 7, 9} {
		if err := os.WriteFile(fmt.Sprintf("%s.before-v%d", p, v), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	ents, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	var snaps []string
	for _, e := range ents {
		if strings.Contains(e.Name(), ".before-") {
			snaps = append(snaps, e.Name())
		}
	}
	want := []string{"yars.db.before-v" + strconv.Itoa(schemaVersion-1), "yars.db.before-v9"}
	slices.Sort(snaps)
	slices.Sort(want)
	if !slices.Equal(snaps, want) {
		t.Fatalf("snapshots %v, want %v", snaps, want)
	}
}

// A new database has nothing to keep.
func TestFreshDatabaseHasNoSnapshot(t *testing.T) {
	_, p := open(t)
	ents, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range ents {
		if strings.Contains(e.Name(), ".before-") {
			t.Fatalf("snapshot %s", e.Name())
		}
	}
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
