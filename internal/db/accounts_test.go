package db

import (
	"database/sql"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"yars/internal/config"
)

func TestUserFlags(t *testing.T) {
	d, _ := open(t)
	if err := d.AddUser(config.User{Username: "ann", Role: "pentester", IsAdmin: true, Theme: "dark"}); err != nil {
		t.Fatal(err)
	}
	u, _, _ := d.User("ann")
	if !u.IsAdmin || u.Disabled || u.Theme != "dark" {
		t.Fatalf("ann %+v", u)
	}
	if err := d.SetAdmin("ann", false); err != nil {
		t.Fatal(err)
	}
	if err := d.SetTheme("ann", "light"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetTheme("ann", "pink"); err == nil {
		t.Fatal("unknown theme accepted")
	}
	d.CreateSession("s1", "ann")
	if err := d.SetDisabled("ann", true); err != nil {
		t.Fatal(err)
	}
	u, _, _ = d.User("ann")
	if u.IsAdmin || !u.Disabled || u.Theme != "light" {
		t.Fatalf("ann %+v", u)
	}
	if _, ok, _ := d.SessionUser("s1"); ok {
		t.Fatal("session of a disabled user survived")
	}
	if err := d.SetAdmin("ghost", true); err == nil {
		t.Fatal("admin set on unknown user")
	}
	us, _ := d.Users()
	if len(us) != 1 || !us[0].Disabled {
		t.Fatalf("users %+v", us)
	}
}

func TestScopedTokens(t *testing.T) {
	d, _ := open(t)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	id, err := d.CreateToken("bob", "h1", "3f2a", TokenSpec{Name: "laptop", Kind: "git", Scopes: []string{"read"},
		Engagements: []string{"acme"}, Expires: now.Add(time.Hour).Format(time.RFC3339)})
	if err != nil || id == 0 {
		t.Fatal(id, err)
	}
	ti, ok, err := d.TokenByHash("h1")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ti.ID != id || ti.User != "bob" || ti.Name != "laptop" || ti.Kind != "git" || ti.Last4 != "3f2a" ||
		!slices.Equal(ti.Scopes, []string{"read"}) || !slices.Equal(ti.Engagements, []string{"acme"}) || ti.LastUsed != "" {
		t.Fatalf("token %+v", ti)
	}
	if _, err := d.CreateToken("bob", "h2", "0000", TokenSpec{Kind: "ftp"}); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if _, err := d.CreateToken("bob", "h2", "0000", TokenSpec{Kind: "mcp", Scopes: []string{"fly"}}); err == nil {
		t.Fatal("unknown scope accepted")
	}
	// last use is recorded at most once a minute
	d.TokenUsed(id)
	ti, _, _ = d.TokenByHash("h1")
	first := ti.LastUsed
	if first == "" {
		t.Fatal("last use not recorded")
	}
	now = now.Add(30 * time.Second)
	d.TokenUsed(id)
	if ti, _, _ = d.TokenByHash("h1"); ti.LastUsed != first {
		t.Fatal("last use written twice within a minute")
	}
	now = now.Add(time.Minute)
	d.TokenUsed(id)
	if ti, _, _ = d.TokenByHash("h1"); ti.LastUsed == first {
		t.Fatal("last use not refreshed after a minute")
	}
	// legacy tokens (yars token add, tokens.yaml) have every right
	d.AddToken("bob", "h3")
	full, _, _ := d.TokenByHash("h3")
	if full.Kind != "mcp" || !full.Allows("status") || !full.AllowsEng("any") {
		t.Fatalf("legacy %+v", full)
	}
	if mine, _ := d.UserTokens("bob"); len(mine) != 2 {
		t.Fatalf("bob's tokens %+v", mine)
	}
	// revoke one by id; another user can't revoke it
	d.AddUser(config.User{Username: "eve", Role: "pentester"})
	if err := d.RevokeToken(id, "eve"); err == nil {
		t.Fatal("eve revoked bob's token")
	}
	if err := d.RevokeToken(id, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := d.TokenByHash("h1"); ok {
		t.Fatal("revoked token found")
	}
	if _, ok, _ := d.TokenByHash("h3"); !ok {
		t.Fatal("revoking one token dropped another")
	}
	if err := d.RevokeToken(full.ID, ""); err != nil { // an admin revokes any
		t.Fatal(err)
	}
}

func TestTokenRights(t *testing.T) {
	read := TokenInfo{Scopes: []string{"read"}}
	if !read.Allows("read") || read.Allows("edit") {
		t.Fatal("read scope")
	}
	some := TokenInfo{Scopes: []string{"edit", "comment"}, Engagements: []string{"acme"}}
	if !some.Allows("read") || !some.Allows("edit") || some.Allows("status") {
		t.Fatal("action scopes")
	}
	if !some.AllowsEng("acme") || some.AllowsEng("other") {
		t.Fatal("engagement list")
	}
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	if (TokenInfo{Expires: "2026-11-05T11:00:00Z"}).Valid(now) || !(TokenInfo{Expires: "2026-11-05T13:00:00Z"}).Valid(now) || !(TokenInfo{}).Valid(now) {
		t.Fatal("expiry")
	}
}

func TestMembersAndArchive(t *testing.T) {
	d, _ := open(t)
	d.AddUser(config.User{Username: "pen", Role: "pentester"})
	d.AddUser(config.User{Username: "rev", Role: "reviewer"})
	s0, _ := d.SeqFor("acme")
	if err := d.AddMembers("acme", "pen", "rev"); err != nil {
		t.Fatal(err)
	}
	if s1, _ := d.SeqFor("acme"); s1 == s0 {
		t.Fatal("membership change did not bump the engagement")
	}
	d.AddMembers("acme", "pen") // again: no error, no duplicate
	if m, _ := d.Members("acme"); !slices.Equal(m, []string{"pen", "rev"}) {
		t.Fatalf("members %v", m)
	}
	if ok, _ := d.IsMember("acme", "pen"); !ok {
		t.Fatal("pen not a member")
	}
	d.AddMembers("beta", "pen")
	if es, _ := d.MemberOf("pen"); !es["acme"] || !es["beta"] || len(es) != 2 {
		t.Fatalf("pen in %v", es)
	}
	if err := d.RemoveMember("acme", "rev"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := d.IsMember("acme", "rev"); ok {
		t.Fatal("rev still a member")
	}
	// a deleted account leaves its teams
	d.DeleteUser("pen")
	if m, _ := d.Members("beta"); len(m) != 0 {
		t.Fatalf("beta %v", m)
	}

	if m, _ := d.EngMeta("acme"); m.Archived {
		t.Fatal("archived from the start")
	}
	if err := d.Archive("acme", "dora"); err != nil {
		t.Fatal(err)
	}
	m, _ := d.EngMeta("acme")
	if !m.Archived || m.ArchivedBy != "dora" || m.ArchivedAt == "" {
		t.Fatalf("meta %+v", m)
	}
	if all, _ := d.ArchivedEngagements(); !all["acme"].Archived || len(all) != 1 {
		t.Fatalf("archived %v", all)
	}
	d.Tx(func(tx *Tx) error {
		if a, _ := tx.Archived("acme"); !a {
			t.Error("tx does not see the archive")
		}
		return nil
	})
	if err := d.Unarchive("acme"); err != nil {
		t.Fatal(err)
	}
	if m, _ := d.EngMeta("acme"); m.Archived {
		t.Fatal("still archived")
	}
	// a new engagement with the old name starts with no team and open
	d.AddMembers("acme", "rev")
	d.Archive("acme", "dora")
	d.Tx(func(tx *Tx) error { return tx.Purge("acme") })
	if m, _ := d.Members("acme"); len(m) != 0 {
		t.Fatalf("team survived purge: %v", m)
	}
	if m, _ := d.EngMeta("acme"); m.Archived {
		t.Fatal("archive survived purge")
	}
}

func TestAudit(t *testing.T) {
	d, _ := open(t)
	s0, _ := d.Seq()
	if err := d.Audit("dora", "user.add", "pen", "role pentester"); err != nil {
		t.Fatal(err)
	}
	d.Audit("pen", "login.fail", "", "")
	if s1, _ := d.Seq(); s1 != s0 {
		t.Fatal("audit bumped the change counter")
	}
	l, err := d.AuditLog(10)
	if err != nil || len(l) != 2 {
		t.Fatal(l, err)
	}
	if l[0].Action != "login.fail" || l[1].Actor != "dora" || l[1].Target != "pen" || l[1].Detail != "role pentester" || l[1].TS == "" {
		t.Fatalf("log %+v", l)
	}
	if l, _ := d.AuditLog(1); len(l) != 1 {
		t.Fatal("limit")
	}
}

func TestConnectionsAndNotify(t *testing.T) {
	d, _ := open(t)
	d.AddUser(config.User{Username: "pen", Role: "pentester"})
	if err := d.SetConnection("pen", "jira", "enc1"); err != nil {
		t.Fatal(err)
	}
	d.SetConnection("pen", "jira", "enc2") // replaces
	if v, ok, _ := d.Connection("pen", "jira"); !ok || v != "enc2" {
		t.Fatalf("connection %q %v", v, ok)
	}
	if cs, _ := d.Connections("pen"); len(cs) != 1 || cs[0].Service != "jira" || cs[0].Created == "" {
		t.Fatalf("connections %+v", cs)
	}
	d.DeleteConnection("pen", "jira")
	if _, ok, _ := d.Connection("pen", "jira"); ok {
		t.Fatal("connection not deleted")
	}
	if err := d.SetNotify("pen", "returned", "email", true); err != nil {
		t.Fatal(err)
	}
	d.SetNotify("pen", "returned", "app", true)
	d.SetNotify("pen", "returned", "app", false)
	if p, _ := d.NotifyPrefs("pen"); !slices.Equal(p["returned"], []string{"email"}) || len(p) != 1 {
		t.Fatalf("prefs %v", p)
	}
}

// A database from before accounts v5: directors become admins, existing
// tokens keep every right, and every user stays on the engagements that
// already have data.
func TestMigrateV5(t *testing.T) {
	p := filepath.Join(t.TempDir(), "yars.db")
	raw, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range migrations[:4] {
		if _, err := raw.Exec(m); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		"PRAGMA user_version = 4",
		"INSERT INTO users(username, role, created) VALUES ('dora', 'director', 'x'), ('pen', 'pentester', 'x')",
		"INSERT INTO tokens(hash, username, created) VALUES ('h1', 'pen', 'x')",
		"INSERT INTO changes_eng(eng, seq) VALUES ('acme', 3)",
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	raw.Close()
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if u, _, _ := d.User("dora"); !u.IsAdmin {
		t.Fatal("director not admin")
	}
	if u, _, _ := d.User("pen"); u.IsAdmin {
		t.Fatal("pentester admin")
	}
	ti, ok, _ := d.TokenByHash("h1")
	if !ok || ti.ID == 0 || ti.Kind != "mcp" || !ti.Allows("status") {
		t.Fatalf("token %+v %v", ti, ok)
	}
	if ok, _ := d.IsMember("acme", "pen"); !ok {
		t.Fatal("pen lost acme")
	}
}
