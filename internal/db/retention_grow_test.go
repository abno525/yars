package db

import (
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
)

// Webhook deliveries (whole payloads) and notifications are pruned with the
// check runs' days. What stays whatever its age: a delivery still waiting,
// each webhook's newest delivery (the Last delivery column, Redeliver). An
// unread notification goes as a read one once it is that old
// (TestPruneUnreadNotifications). 0 keeps all.
func TestPruneDeliveriesAndNotifications(t *testing.T) {
	d, _ := open(t)
	now := time.Now()
	year := at(now.AddDate(-1, 0, 0))
	h1, _ := d.AddWebhook(Webhook{URL: "https://a.test/", Events: []string{"finding.updated"}, SecretEnc: "x", Enabled: true})
	h2, _ := d.AddWebhook(Webhook{URL: "https://b.test/", Events: []string{"finding.updated"}, SecretEnc: "x", Enabled: true})
	add := func(hook int64, done bool) int64 {
		t.Helper()
		id, err := d.EnqueueDelivery(hook, "finding.updated", `{"text":"x"}`, now)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			if err := d.FinishAttempt(id, 200, "", time.Time{}, now); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	age := func(ids ...int64) {
		t.Helper()
		for _, id := range ids {
			if _, err := d.Exec("UPDATE webhook_deliveries SET created = ?, next_at = ?, finished = CASE WHEN finished = '' THEN '' ELSE ? END WHERE id = ?", year, year, year, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	oldOK, oldFailed, oldPending, fresh := add(h1, true), add(h1, false), add(h1, false), add(h1, true)
	if err := d.FinishAttempt(oldFailed, 500, "HTTP 500", time.Time{}, now); err != nil { // given up
		t.Fatal(err)
	}
	age(oldOK, oldFailed, oldPending)
	only := add(h2, true) // the one delivery of its webhook, a year old
	age(only)

	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	note := func(read, old bool) int64 {
		t.Helper()
		id, err := d.AddNotification(Notification{User: "bob", Event: "mention", Text: "x"})
		if err != nil {
			t.Fatal(err)
		}
		if read {
			d.MarkRead("bob", id)
		}
		if old {
			d.Exec("UPDATE notifications SET ts = ? WHERE id = ?", year, id)
		}
		return id
	}
	oldRead, oldUnread, newRead, newUnread := note(true, true), note(false, true), note(true, false), note(false, false)

	if p, err := d.Prune(now, Retention{AuditDays: 30}); err != nil || p != (Pruned{}) {
		t.Fatalf("check run days 0 pruned %+v %v", p, err)
	}
	p, err := d.Prune(now, Retention{CheckRunDays: 90})
	if err != nil || p != (Pruned{Deliveries: 2, Notifications: 2}) {
		t.Fatalf("pruned %+v %v", p, err)
	}
	for _, id := range []int64{oldOK, oldFailed} {
		if _, err := d.Delivery(id); err == nil {
			t.Errorf("finished delivery %d of a year ago was kept", id)
		}
	}
	for name, id := range map[string]int64{"a waiting delivery": oldPending, "a new delivery": fresh, "a webhook's newest delivery": only} {
		if _, err := d.Delivery(id); err != nil {
			t.Errorf("%s was deleted: %v", name, err)
		}
	}
	for name, id := range map[string]int64{"a read notification": oldRead, "an unread notification": oldUnread} {
		if _, ok, _ := d.NotificationByID("bob", id); ok {
			t.Errorf("%s of a year ago was kept", name)
		}
	}
	for name, id := range map[string]int64{"a new unread notification": newUnread, "a new notification": newRead} {
		if _, ok, _ := d.NotificationByID("bob", id); !ok {
			t.Errorf("%s was deleted", name)
		}
	}
	if l, _ := d.LastDeliveries(); l[h1].ID != fresh || l[h2].ID != only {
		t.Fatalf("last deliveries %+v", l)
	}
}

// A notification nobody read is pruned too, so the table is bounded for an
// account that never opens its list: after the check runs' days, but never
// before it is UnreadNoticeDays old (short days must not empty the list of
// someone who was away). 0 keeps all.
func TestPruneUnreadNotifications(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		name       string
		days       int
		read       bool
		age        int // days
		wantPruned bool
	}{
		{"unread, a year old, 90 days", 90, false, 365, true},
		{"unread, 100 days old, 90 days", 90, false, 100, true},
		{"unread, 60 days old, 90 days", 90, false, 60, false},
		{"unread, new, 90 days", 90, false, 0, false},
		{"unread, 60 days old, 7 days", 7, false, 60, false},
		{"read, 60 days old, 7 days", 7, true, 60, true},
		{"unread, 100 days old, 7 days", 7, false, 100, true},
		{"unread, 100 days old, 365 days", 365, false, 100, false},
		{"unread, 400 days old, 365 days", 365, false, 400, true},
		{"unread, a year old, 0 days", 0, false, 365, false},
	} {
		d, _ := open(t)
		d.AddUser(config.User{Username: "bob", Role: "reviewer"})
		id, err := d.AddNotification(Notification{User: "bob", Event: "mention", Text: "x"})
		if err != nil {
			t.Fatal(err)
		}
		if c.read {
			d.MarkRead("bob", id)
		}
		if _, err := d.Exec("UPDATE notifications SET ts = ? WHERE id = ?", at(now.AddDate(0, 0, -c.age)), id); err != nil {
			t.Fatal(err)
		}
		p, err := d.Prune(now, Retention{CheckRunDays: c.days})
		if err != nil {
			t.Fatal(err)
		}
		_, kept, _ := d.NotificationByID("bob", id)
		if kept == c.wantPruned || (p.Notifications == 1) != c.wantPruned {
			t.Errorf("%s: kept %v, counted %d", c.name, kept, p.Notifications)
		}
	}
}

// The audit log's prune and its date filter read by time: the table has an
// index on it, on a new database and on an upgraded one.
func TestAuditTimeIndex(t *testing.T) {
	has := func(d *DB) int {
		var n int
		if err := d.QueryRow("SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'audit_ts' AND tbl_name = 'audit'").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	d, _ := open(t)
	if has(d) != 1 {
		t.Fatal("a new database has no index audit_ts")
	}
	up, err := Open(openAtVersion(t, legacySchema))
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	if has(up) != 1 {
		t.Fatal("an upgraded database has no index audit_ts")
	}
}
