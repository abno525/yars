package db

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"yars/internal/config"
)

func TestServerSettings(t *testing.T) {
	d, _ := open(t)
	if v, err := d.Setting("ai.model"); err != nil || v != "" {
		t.Fatalf("unset: %q %v", v, err)
	}
	if err := d.SetSetting("ai.model", "m1"); err != nil {
		t.Fatal(err)
	}
	d.SetSetting("ai.model", "m2")
	d.SetSetting("ai.provider", "openai")
	if v, _ := d.Setting("ai.model"); v != "m2" {
		t.Fatalf("model %q", v)
	}
	all, err := d.Settings("ai.")
	if err != nil || len(all) != 2 || all["ai.provider"] != "openai" {
		t.Fatalf("settings %v %v", all, err)
	}
	// an empty value removes the setting
	d.SetSetting("ai.model", "")
	if all, _ := d.Settings("ai."); len(all) != 1 {
		t.Fatalf("after clear %v", all)
	}
}

func TestEmailCreatedAndFirstUser(t *testing.T) {
	d, _ := open(t)
	if n, _ := d.UserCount(); n != 0 {
		t.Fatalf("count %d", n)
	}
	if err := d.AddFirstUser(config.User{Username: "dir1", Role: "director", IsAdmin: true}); err != nil {
		t.Fatal(err)
	}
	if err := d.AddFirstUser(config.User{Username: "dir2", Role: "director", IsAdmin: true}); !errors.Is(err, ErrNotFirst) {
		t.Fatalf("second first user: %v", err)
	}
	if n, _ := d.UserCount(); n != 1 {
		t.Fatalf("count %d", n)
	}
	if err := d.SetEmail("dir1", "d@x"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetEmail("ghost", "g@x"); err == nil {
		t.Fatal("email set on unknown user")
	}
	u, _, _ := d.User("dir1")
	if u.Email != "d@x" || u.Created == "" || !u.IsAdmin {
		t.Fatalf("dir1 %+v", u)
	}
}

func TestSessionsList(t *testing.T) {
	d, _ := open(t)
	d.AddUser(config.User{Username: "ann", Role: "pentester"})
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	d.CreateSession("h1", "ann")
	d.CreateSession("h2", "bob")
	ss, err := d.Sessions()
	if err != nil || len(ss) != 2 {
		t.Fatalf("sessions %+v %v", ss, err)
	}
	var bob SessionInfo
	for _, s := range ss {
		if s.ID == 0 || s.Created == "" || s.LastSeen == "" {
			t.Fatalf("session %+v", s)
		}
		if s.User == "bob" {
			bob = s
		}
	}
	if err := d.DeleteSessionID(bob.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := d.SessionUser("h2"); ok {
		t.Fatal("revoked session still works")
	}
	if _, ok, _ := d.SessionUser("h1"); !ok {
		t.Fatal("other session revoked")
	}
	if err := d.DeleteSessionID(bob.ID); err == nil {
		t.Fatal("second revoke succeeded")
	}
}

func TestSnapshot(t *testing.T) {
	d, _ := open(t)
	d.AddUser(config.User{Username: "ann", Role: "pentester"})
	p := filepath.Join(t.TempDir(), "snap.db")
	if err := d.Snapshot(p); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var n int
	if err := raw.QueryRow("SELECT count(*) FROM users").Scan(&n); err != nil || n != 1 {
		t.Fatalf("snapshot users %d %v", n, err)
	}
	if c, err := d.ChatCount(); err != nil || c != 0 {
		t.Fatalf("chat count %d %v", c, err)
	}
	if n, err := d.Size(); err != nil || n < 4096 {
		t.Fatalf("size %d %v", n, err)
	}
	if res, err := d.Check(); err != nil || res != "ok" {
		t.Fatalf("check %q %v", res, err)
	}
	if v, err := d.Version(); err != nil || v != SchemaVersion {
		t.Fatalf("version %d %v", v, err)
	}
}

func TestAuditFilter(t *testing.T) {
	d, _ := open(t)
	d.Audit("ann", "login", "", "")
	d.Audit("bob", "login.fail", "", "")
	d.Audit("ann", "token.create", "ann", "#1")
	d.Audit("dir1", "eng.archive", "acme", "")
	l, total, err := d.AuditQuery(AuditFilter{Actor: "ann", Limit: 10})
	if err != nil || total != 2 || len(l) != 2 || l[0].Action != "token.create" {
		t.Fatalf("by actor %+v %d %v", l, total, err)
	}
	l, total, _ = d.AuditQuery(AuditFilter{Action: "login", Limit: 10})
	if total != 2 || len(l) != 2 {
		t.Fatalf("by action group %+v", l)
	}
	l, total, _ = d.AuditQuery(AuditFilter{Limit: 1, Offset: 1})
	if total != 4 || len(l) != 1 || l[0].Action != "token.create" {
		t.Fatalf("paged %+v %d", l, total)
	}
	actors, _ := d.AuditActors()
	if len(actors) != 3 || actors[0] != "ann" {
		t.Fatalf("actors %v", actors)
	}
}
