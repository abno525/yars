package db

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"
)

// A notification remembers the chat thread it is about (028): a database of
// the schema before gets the column once, its rows keep an empty thread, and
// the step may run again.
func TestNotificationThreadMigration(t *testing.T) {
	const name = "028-notification-thread"
	i := slices.IndexFunc(migrations, func(m migration) bool { return m.name == name })
	if i < 0 {
		t.Fatalf("no migration %s", name)
	}
	p := filepath.Join(t.TempDir(), "yars.db")
	d := rawDB(t, p)
	if err := d.migrateTo(p, slices.Delete(slices.Clone(migrations), i, i+1)); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"INSERT INTO users(username, role, created) VALUES ('alice', 'pentester', '2026-01-01T00:00:00Z')",
		"INSERT INTO notifications(username, event, eng, dir, fid, title, ts) VALUES ('alice', 'reply', 'acme', 'F-001-x', 'F-001', 'X', '2026-01-01T00:00:00Z')",
	} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.migrate(p); err != nil {
		t.Fatal(err)
	}
	if v := userVersion(t, d); v != len(migrations) {
		t.Fatalf("user_version %d, want %d", v, len(migrations))
	}
	var thread string
	if err := d.QueryRow("SELECT thread FROM notifications WHERE username = 'alice'").Scan(&thread); err != nil || thread != "" {
		t.Fatalf("the old row's thread %q, %v", thread, err)
	}
	if got := snapshots(t, p); len(got) != 1 || got[0] != fmt.Sprintf("yars.db.before-v%d", len(migrations)-1) {
		t.Fatalf("snapshots %v", got)
	}
	rerun(t, d, name)
	if n := count(t, d, "notifications"); n != 1 {
		t.Fatalf("%d rows after the step ran again", n)
	}
}

// A notification is stored and read with its thread, and MarkFindingRead
// marks one account's unread notices of one finding, by its ID.
func TestNotificationThreadAndFindingRead(t *testing.T) {
	d, _ := open(t)
	for _, u := range []string{"alice", "bob"} {
		if _, err := d.Exec("INSERT INTO users(username, role, created) VALUES (?, 'pentester', '2026-01-01T00:00:00Z')", u); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []Notification{
		{User: "alice", Event: "reply", Eng: "acme", Dir: "F-001-old-name", Fid: "F-001", Thread: "abc123"},
		{User: "alice", Event: "returned", Eng: "acme", Dir: "F-001-new-name", Fid: "F-001"},
		{User: "alice", Event: "reply", Eng: "acme", Dir: "F-002-x", Fid: "F-002"},
		{User: "alice", Event: "reply", Eng: "beta", Dir: "F-001-x", Fid: "F-001"},
		{User: "alice", Event: "token"},
		{User: "bob", Event: "reply", Eng: "acme", Dir: "F-001-new-name", Fid: "F-001"},
	} {
		if _, err := d.AddNotification(n); err != nil {
			t.Fatal(err)
		}
	}
	l, err := d.Notifications("alice", 10)
	if err != nil || len(l) != 5 || l[4].Thread != "abc123" || l[3].Thread != "" {
		t.Fatalf("notifications %+v, %v", l, err)
	}
	if n, ok, err := d.NotificationByID("alice", l[4].ID); err != nil || !ok || n.Thread != "abc123" {
		t.Fatalf("by id %+v %v %v", n, ok, err)
	}
	if page, err := d.NotificationPage("alice", true, false, nil, 0, 10); err != nil || len(page) != 5 || page[4].Thread != "abc123" {
		t.Fatalf("page %+v, %v", page, err)
	}
	unread := func(user string) int {
		t.Helper()
		n, err := d.UnreadCount(user)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, args := range [][2]string{{"", "F-001"}, {"acme", ""}, {"acme", "F-009"}} {
		if err := d.MarkFindingRead("alice", args[0], args[1]); err != nil || unread("alice") != 5 {
			t.Fatalf("%v marked something: %v", args, err)
		}
	}
	if err := d.MarkFindingRead("alice", "acme", "F-001"); err != nil {
		t.Fatal(err)
	}
	if a, b := unread("alice"), unread("bob"); a != 3 || b != 1 {
		t.Fatalf("unread after: alice %d (want 3), bob %d (want 1)", a, b)
	}
}
