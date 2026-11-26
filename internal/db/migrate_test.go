package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// legacyNames are the migrations the builds without names knew, in their
// order: a database of theirs says only how many of these it ran, so the
// list starts with them for good.
var legacyNames = []string{
	"001-accounts-state-chat", "002-engagement-change-counters", "003-withdrawn-and-hidden-threads",
	"004-check-runs-and-dismissals", "005-admin-flag-tokens-teams-audit", "006-server-settings",
	"007-export-history", "008-webhooks-and-notifications", "009-export-remote",
	"010-check-steps-dismiss-reason", "011-team-backfill-pending", "012-team-board",
	"013-check-runs-stored", "014-dismissals-per-row", "015-must-change-password", "016-login-attempts",
	"017-end-copied-legacy-dismissals", "018-cut-off-runs-not-stored", "019-check-runs-rules-version",
	"020-ai-usage", "021-redactions", "022-keys-off", "023-token-expiry-noted", "024-rule-cache",
}

// Every migration has a name of its own, and the first ones keep theirs.
func TestMigrationNames(t *testing.T) {
	seen := map[string]bool{}
	for i, m := range migrations {
		if m.name == "" || seen[m.name] {
			t.Fatalf("migration %d: name %q is empty or used twice", i+1, m.name)
		}
		seen[m.name] = true
		if m.sql == "" && m.fn == nil {
			t.Fatalf("%s does nothing", m.name)
		}
	}
	if legacySchema != len(legacyNames) || len(migrations) < legacySchema {
		t.Fatalf("legacySchema %d, %d migrations", legacySchema, len(migrations))
	}
	for i, want := range legacyNames {
		if migrations[i].name != want {
			t.Fatalf("migration %d is %q, want %q", i+1, migrations[i].name, want)
		}
	}
	if SchemaVersion != len(migrations) {
		t.Fatalf("SchemaVersion %d, %d migrations", SchemaVersion, len(migrations))
	}
}

// rawDB opens the database file at p without migrating it.
func rawDB(t *testing.T, p string) *DB {
	t.Helper()
	sdb, err := sql.Open("sqlite", fileURI(p)+"?_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sdb.Close() })
	return &DB{DB: sdb, now: time.Now}
}

// applied are the names the database recorded, sorted.
func applied(t *testing.T, d *DB) []string {
	t.Helper()
	rows, err := d.Query("SELECT name FROM schema_migrations ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func userVersion(t *testing.T, d *DB) int {
	t.Helper()
	var v int
	if err := d.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// snapshots are the .before- files beside the database at p.
func snapshots(t *testing.T, p string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Dir(p))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if strings.Contains(e.Name(), ".before-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// schemaText is the database's schema but for the table of names.
func schemaText(t *testing.T, d *DB) string {
	t.Helper()
	rows, err := d.Query("SELECT type || ' ' || name || ' ' || coalesce(sql, '') FROM sqlite_master WHERE name NOT LIKE 'schema_migrations%' AND name NOT LIKE 'sqlite_%' ORDER BY type, name")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		b.WriteString(s + "\n")
	}
	return b.String()
}

// rerun makes a current database forget that it applied the named
// migrations and migrates it again: only those run.
func rerun(t *testing.T, d *DB, names ...string) {
	t.Helper()
	for _, n := range names {
		res, err := d.Exec("DELETE FROM schema_migrations WHERE name = ?", n)
		if err != nil {
			t.Fatal(err)
		}
		if c, _ := res.RowsAffected(); c != 1 {
			t.Fatalf("%s was not applied", n)
		}
	}
	if _, err := d.Exec(fmt.Sprintf("PRAGMA user_version = %d", len(applied(t, d)))); err != nil {
		t.Fatal(err)
	}
	if err := d.migrate(filepath.Join(t.TempDir(), "yars.db")); err != nil {
		t.Fatal(err)
	}
}

// A migration added before one a database already applied runs on that
// database, and the later one does not run again: the names decide, not the
// place in the list.
func TestInsertedMigrationRuns(t *testing.T) {
	d, p := open(t)
	last := migration{name: "t-last", sql: "CREATE TABLE t_last (x TEXT)"}
	if err := d.migrateTo(p, append(slices.Clone(migrations), last)); err != nil {
		t.Fatal(err)
	}
	ran := 0
	mid := migration{name: "t-mid", sql: "CREATE TABLE t_mid (x TEXT)", fn: func(*sql.Tx) error { ran++; return nil }}
	list := append(slices.Clone(migrations), mid, last)
	if err := d.migrateTo(p, list); err != nil {
		t.Fatalf("with a migration added before the last: %v", err)
	}
	if n := count(t, d, "t_mid"); n != 0 || ran != 1 {
		t.Fatalf("the added migration ran %d times", ran)
	}
	if v := userVersion(t, d); v != len(list) {
		t.Fatalf("user_version %d, want %d", v, len(list))
	}
	if got := applied(t, d); !slices.Contains(got, "t-mid") || !slices.Contains(got, "t-last") || len(got) != len(list) {
		t.Fatalf("names %v", got)
	}
	// a third open changes nothing
	if err := d.migrateTo(p, list); err != nil || ran != 1 {
		t.Fatalf("reopen: %v, ran %d", err, ran)
	}
}

// A database written by a build that kept no names (the number alone) gets
// its names without any migration running again, and no snapshot: nothing of
// its schema changes.
func TestLegacyDatabaseGetsNames(t *testing.T) {
	list := migrations[:legacySchema]
	p := openAtVersion(t, legacySchema)
	d := rawDB(t, p)
	for _, q := range []string{
		// v5 would make the director an admin, v13 would mark the run stored
		"INSERT INTO users(username, role, created, is_admin) VALUES ('dora', 'director', 'x', 0)",
		"INSERT INTO check_runs(eng, fid, content_hash, started, finished, state, by_user, stored) VALUES ('e', 'F-001', 'h', 'x', 'x', 'done', 'dora', 0)",
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	before := schemaText(t, d)
	for range 2 {
		if err := d.migrateTo(p, list); err != nil {
			t.Fatal(err)
		}
	}
	var admin, stored int
	if err := d.QueryRow("SELECT is_admin FROM users WHERE username = 'dora'").Scan(&admin); err != nil || admin != 0 {
		t.Fatalf("is_admin %d %v: v5 ran again", admin, err)
	}
	if err := d.QueryRow("SELECT stored FROM check_runs").Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("stored %d %v: v13 ran again", stored, err)
	}
	if got := applied(t, d); !slices.Equal(got, legacyNames) {
		t.Fatalf("names %v", got)
	}
	if v := userVersion(t, d); v != legacySchema {
		t.Fatalf("user_version %d", v)
	}
	if s := snapshots(t, p); len(s) != 0 {
		t.Fatalf("snapshots %v", s)
	}
	if after := schemaText(t, d); after != before {
		t.Fatalf("schema changed:\n%s\nwas:\n%s", after, before)
	}
}

// An older legacy database runs every later migration once and keeps a copy
// of itself as it was.
func TestLegacyDatabaseUpgrades(t *testing.T) {
	fresh, _ := open(t)
	want := schemaText(t, fresh)
	for _, v := range []int{1, 10, 13, 23, legacySchema} {
		t.Run(fmt.Sprint(v), func(t *testing.T) {
			p := openAtVersion(t, v)
			d, err := Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if got := schemaText(t, d); got != want {
				t.Fatalf("schema\n%s\nwant\n%s", got, want)
			}
			if got := applied(t, d); len(got) != len(migrations) {
				t.Fatalf("names %v", got)
			}
			if got := userVersion(t, d); got != schemaVersion {
				t.Fatalf("user_version %d", got)
			}
			snaps := snapshots(t, p)
			if v == schemaVersion {
				if len(snaps) != 0 {
					t.Fatalf("snapshots %v", snaps)
				}
				return
			}
			if want := []string{fmt.Sprintf("yars.db.before-v%d", v)}; !slices.Equal(snaps, want) {
				t.Fatalf("snapshots %v, want %v", snaps, want)
			}
			if sv, err := SchemaOf(filepath.Join(filepath.Dir(p), snaps[0])); err != nil || sv != v {
				t.Fatalf("snapshot schema %d %v", sv, err)
			}
		})
	}
}

// A database that applied a migration this build does not know was written
// by a newer or another build: it is not opened.
func TestUnknownMigrationRefused(t *testing.T) {
	d, p := open(t)
	if _, err := d.Exec("UPDATE schema_migrations SET name = 't-other' WHERE name = ?", migrations[len(migrations)-1].name); err != nil {
		t.Fatal(err)
	}
	d.Close()
	_, err := Open(p)
	if err == nil || !strings.Contains(err.Error(), `"t-other"`) {
		t.Fatalf("opened a database with an unknown migration: %v", err)
	}
	if s := snapshots(t, p); len(s) != 0 {
		t.Fatalf("snapshots %v", s)
	}
}

// The names are what counts: a number set lower by hand runs nothing again
// and is put right; a number higher than the names is refused.
func TestNumberFollowsNames(t *testing.T) {
	d, p := open(t)
	if _, err := d.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion-1)); err != nil {
		t.Fatal(err)
	}
	if err := d.migrate(p); err != nil {
		t.Fatal(err)
	}
	if v := userVersion(t, d); v != schemaVersion {
		t.Fatalf("user_version %d", v)
	}
	if s := snapshots(t, p); len(s) != 0 {
		t.Fatalf("snapshots %v", s)
	}
	if _, err := d.Exec("DELETE FROM schema_migrations WHERE name = ?", migrations[0].name); err != nil {
		t.Fatal(err)
	}
	if err := d.migrate(p); err == nil {
		t.Fatal("migrated a database whose number is higher than its names")
	}
}
