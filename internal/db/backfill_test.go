package db

import (
	"database/sql"
	"path/filepath"
	"slices"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// The v5 backfill put people only on engagements with a change counter row;
// the one-time team backfill (pending since v11) puts every account on the
// engagements on disk whose team is empty and was never managed.
func TestBackfillTeams(t *testing.T) {
	p := filepath.Join(t.TempDir(), "yars.db")
	raw, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	legacySQL(t, raw, 10)
	for _, q := range []string{
		"PRAGMA user_version = 10",
		"INSERT INTO users(username, role, created) VALUES ('dora', 'director', 'x'), ('pen', 'pentester', 'x')",
		"INSERT INTO engagement_members(eng, username) VALUES ('acme', 'dora')",
		// a team emptied on purpose stays empty
		"INSERT INTO audit(ts, actor, action, target) VALUES ('x', 'dora', 'eng.member.remove', 'gamma')",
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
	if err := d.BackfillTeams([]string{"acme", "beta", "gamma"}); err != nil {
		t.Fatal(err)
	}
	for eng, want := range map[string][]string{"acme": {"dora"}, "beta": {"dora", "pen"}, "gamma": {}} {
		if got, _ := d.Members(eng); !slices.Equal(got, want) {
			t.Errorf("%s team %v, want %v", eng, got, want)
		}
	}
	// once only: a later empty team is left alone
	if err := d.BackfillTeams([]string{"delta"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.Members("delta"); len(got) != 0 {
		t.Fatalf("second backfill filled %v", got)
	}
}

// The backfill runs at every start, so it fills an archived engagement with
// an empty team too, and the database's own AddMembers and RemoveMember take
// one: the rule that an archived engagement keeps its team is the store's
// (Store.AddMembers), never the database's, or an archived engagement could
// stop yars serve from starting.
func TestBackfillTeamsFillsArchived(t *testing.T) {
	d, _ := open(t)
	if err := d.Archive("old", "dora"); err != nil {
		t.Fatal(err)
	}
	if err := d.AddUser(config.User{Username: "pen", Role: "pentester"}); err != nil {
		t.Fatal(err)
	}
	if err := d.BackfillTeams([]string{"old"}); err != nil {
		t.Fatalf("the backfill of an archived engagement: %v", err)
	}
	if ok, _ := d.IsMember("old", "pen"); !ok {
		t.Fatal("pen not on the archived engagement")
	}
	if err := d.AddMembers("old", "dora"); err != nil {
		t.Fatalf("db.AddMembers on an archived engagement: %v", err)
	}
	if err := d.RemoveMember("old", "pen"); err != nil {
		t.Fatalf("db.RemoveMember on an archived engagement: %v", err)
	}
	if got, _ := d.Members("old"); !slices.Equal(got, []string{"dora"}) {
		t.Fatalf("team %v", got)
	}
}

// Without any account yet the backfill waits: the accounts imported later
// (yars migrate) or made by first-run setup are put on the teams then.
func TestBackfillTeamsWaitsForAccounts(t *testing.T) {
	d, _ := open(t)
	if err := d.BackfillTeams([]string{"acme"}); err != nil {
		t.Fatal(err)
	}
	if err := d.AddUser(config.User{Username: "pen", Role: "pentester"}); err != nil {
		t.Fatal(err)
	}
	if err := d.BackfillTeams([]string{"acme"}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := d.IsMember("acme", "pen"); !ok {
		t.Fatal("pen not on acme")
	}
}
