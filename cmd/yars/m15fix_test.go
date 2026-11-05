package main

import (
	"bytes"
	"testing"

	"yars/internal/auth"
	"yars/internal/config"
)

// Accounts imported by yars migrate get the defaults v5 gave existing
// accounts: directors are admins and everyone is on the engagements that
// exist.
func TestMigrateAccountDefaults(t *testing.T) {
	dir := legacyRepo(t)
	hash, _ := auth.HashPassword("pw")
	users := []config.User{{Username: "alice", Role: "pentester", PasswordHash: hash}, {Username: "bob", Role: "reviewer", PasswordHash: hash}, {Username: "dora", Role: "director", PasswordHash: hash}}
	if err := config.SaveUsers(dir, users); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdMigrate([]string{"--data", dir}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	d := openDB(t, dir)
	if u, _, _ := d.User("dora"); !u.IsAdmin {
		t.Fatal("imported director is not an admin")
	}
	if u, _, _ := d.User("alice"); u.IsAdmin {
		t.Fatal("imported pentester is an admin")
	}
	for _, eng := range []string{"acme", "rt"} {
		if ok, _ := d.IsMember(eng, "alice"); !ok {
			t.Errorf("alice not on %s", eng)
		}
	}
}
