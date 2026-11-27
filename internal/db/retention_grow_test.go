package db

import (
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
)

// Webhook deliveries (whole payloads) and notifications are pruned with the
// check runs' days. What stays whatever its age: a delivery still waiting,
// each webhook's newest delivery (the Last delivery column, Redeliver) and
// an unread notification. 0 keeps all.
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
	oldRead, oldUnread, newRead := note(true, true), note(false, true), note(true, false)

	if p, err := d.Prune(now, Retention{AuditDays: 30}); err != nil || p != (Pruned{}) {
		t.Fatalf("check run days 0 pruned %+v %v", p, err)
	}
	p, err := d.Prune(now, Retention{CheckRunDays: 90})
	if err != nil || p != (Pruned{Deliveries: 2, Notifications: 1}) {
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
	if _, ok, _ := d.NotificationByID("bob", oldRead); ok {
		t.Error("a read notification of a year ago was kept")
	}
	for name, id := range map[string]int64{"an unread notification": oldUnread, "a new notification": newRead} {
		if _, ok, _ := d.NotificationByID("bob", id); !ok {
			t.Errorf("%s was deleted", name)
		}
	}
	if l, _ := d.LastDeliveries(); l[h1].ID != fresh || l[h2].ID != only {
		t.Fatalf("last deliveries %+v", l)
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
