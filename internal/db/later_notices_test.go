package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// An account that saved its notification choices before the later notices
// existed has no row for them, which reads as off: the migration gives it
// the in-app row of each. An account that never chose keeps the default, and
// a second run changes nothing.
func TestLaterNoticeDefaults(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "y.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, n := range []string{"saved", "never"} {
		if err := d.AddUser(config.User{Username: n, Role: "pentester"}); err != nil {
			t.Fatal(err)
		}
	}
	// saved chose once: mail for returned, nothing in app
	if err := d.SetNotifyChoices("saved", []NotifyChoice{{"returned", "email", true}, {"returned", "app", false}}); err != nil {
		t.Fatal(err)
	}
	for _, k := range LaterNoticeKeys {
		if d.Wants("saved", k, "app") {
			t.Fatalf("%s is on before the migration", k)
		}
	}
	run := func() {
		t.Helper()
		tx, err := d.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := laterNoticeDefaults(tx); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	run()
	run()
	for _, k := range LaterNoticeKeys {
		if !d.Wants("saved", k, "app") || d.Wants("saved", k, "email") {
			t.Errorf("%s after the migration: app %v, email %v", k, d.Wants("saved", k, "app"), d.Wants("saved", k, "email"))
		}
		if !d.Wants("never", k, "app") {
			t.Errorf("%s is off for an account that never chose", k)
		}
	}
	// the choice that was made stays
	if d.Wants("saved", "returned", "app") || !d.Wants("saved", "returned", "email") {
		t.Fatal("the migration changed a saved choice")
	}
	var rows int
	if err := d.QueryRow("SELECT count(*) FROM notify_prefs WHERE username = 'never'").Scan(&rows); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("an account that never chose got %d rows", rows)
	}
	if got := migrations[len(migrations)-1].name; got != "030-later-notice-defaults" {
		t.Fatalf("the last migration is %s", got)
	}
}
