package db

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"yars/internal/config"
)

func openTest(t *testing.T) *DB {
	t.Helper()
	d, err := Open(filepath.Join(t.TempDir(), "y.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestWebhooksAndDeliveries(t *testing.T) {
	d := openTest(t)
	if schemaVersion < 8 {
		t.Fatalf("schema %d", schemaVersion)
	}
	id, err := d.AddWebhook(Webhook{URL: "https://hooks.example/a", Events: []string{"chat.posted", "finding.created"}, SecretEnc: "enc", Last4: "3f2a", Enabled: true, CreatedBy: "dora"})
	if err != nil || id == 0 {
		t.Fatal(id, err)
	}
	off, _ := d.AddWebhook(Webhook{URL: "https://hooks.example/b", Events: []string{"chat.posted"}, SecretEnc: "e2", Enabled: false})
	hs, err := d.Webhooks()
	if err != nil || len(hs) != 2 || hs[0].ID != id || !slices.Equal(hs[0].Events, []string{"chat.posted", "finding.created"}) || !hs[0].Enabled || hs[1].Enabled {
		t.Fatalf("%+v %v", hs, err)
	}
	// only enabled hooks that take the event
	if l, _ := d.HooksFor("chat.posted"); len(l) != 1 || l[0].ID != id {
		t.Fatalf("hooks for chat %+v", l)
	}
	if l, _ := d.HooksFor("export.sent"); len(l) != 0 {
		t.Fatalf("hooks for export %+v", l)
	}
	if err := d.UpdateWebhook(off, "https://hooks.example/c", []string{"export.sent"}, true); err != nil {
		t.Fatal(err)
	}
	if h, ok, _ := d.WebhookByID(off); !ok || h.URL != "https://hooks.example/c" || !h.Enabled || h.SecretEnc != "e2" {
		t.Fatalf("%+v", h)
	}
	if err := d.SetWebhookEnabled(off, false); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	did, err := d.EnqueueDelivery(id, "chat.posted", `{"a":1}`, now)
	if err != nil {
		t.Fatal(err)
	}
	later, _ := d.EnqueueDelivery(id, "chat.posted", `{"a":2}`, now.Add(time.Hour))
	due, err := d.DueDeliveries(now, 10)
	if err != nil || len(due) != 1 || due[0].ID != did || due[0].Payload != `{"a":1}` || due[0].HookID != id {
		t.Fatalf("%+v %v", due, err)
	}
	// a failed try waits until next; then it is due again
	if err := d.FinishAttempt(did, 500, "500 Internal Server Error", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	if due, _ := d.DueDeliveries(now, 10); len(due) != 0 {
		t.Fatalf("due before next try %+v", due)
	}
	if due, _ := d.DueDeliveries(now.Add(2*time.Minute), 10); len(due) != 1 || due[0].Attempts != 1 {
		t.Fatalf("due after %+v", due)
	}
	// success
	if err := d.FinishAttempt(did, 204, "", time.Time{}, now); err != nil {
		t.Fatal(err)
	}
	dl, _ := d.Delivery(did)
	if dl.State != DeliveryOK || dl.Status != 204 || dl.Attempts != 2 || dl.Finished == "" {
		t.Fatalf("%+v", dl)
	}
	// given up: no next try
	d.FinishAttempt(later, 0, "connection refused", time.Time{}, now)
	if dl, _ := d.Delivery(later); dl.State != DeliveryFailed || dl.Error != "connection refused" {
		t.Fatalf("%+v", dl)
	}
	last, err := d.LastDeliveries()
	if err != nil || last[id].ID != later {
		t.Fatalf("last %+v %v", last, err)
	}
	if l, _ := d.Deliveries(id, 10); len(l) != 2 || l[0].ID != later {
		t.Fatalf("deliveries %+v", l)
	}
	// redeliver makes a new pending copy
	nid, err := d.Redeliver(later, now)
	if err != nil || nid == later {
		t.Fatal(nid, err)
	}
	if dl, _ := d.Delivery(nid); dl.State != DeliveryPending || dl.Payload != `{"a":2}` || dl.Attempts != 0 {
		t.Fatalf("%+v", dl)
	}
	// deleting a hook drops its deliveries
	if err := d.DeleteWebhook(id); err != nil {
		t.Fatal(err)
	}
	if l, _ := d.Deliveries(id, 10); len(l) != 0 {
		t.Fatal("deliveries kept")
	}
}

func TestNotifications(t *testing.T) {
	d := openTest(t)
	d.AddUser(config.User{Username: "pen", Role: "pentester"})
	d.AddUser(config.User{Username: "rev", Role: "reviewer"})
	// never chosen: in app for every event
	if !d.Wants("pen", "returned", "app") || d.Wants("pen", "returned", "email") {
		t.Fatal("defaults")
	}
	ch, _ := d.NotifyChoices("pen", []string{"returned", "check"})
	if !slices.Equal(ch["returned"], []string{"app"}) || !slices.Equal(ch["check"], []string{"app"}) {
		t.Fatalf("choices %v", ch)
	}
	// once chosen, the choice counts (even when nothing is ticked)
	d.SetNotify("pen", "returned", "email", true)
	if d.Wants("pen", "returned", "app") || !d.Wants("pen", "returned", "email") || d.Wants("pen", "check", "app") {
		t.Fatal("saved choice")
	}

	id, err := d.AddNotification(Notification{User: "pen", Event: "returned", Eng: "acme", Dir: "F-001-sqli", Fid: "F-001", Title: "SQLi", Actor: "rev", Text: "add a PoC"})
	if err != nil || id == 0 {
		t.Fatal(id, err)
	}
	d.AddNotification(Notification{User: "pen", Event: "mentioned", Eng: "acme", Fid: "F-002", Actor: "rev"})
	d.AddNotification(Notification{User: "rev", Event: "review", Eng: "acme", Fid: "F-001"})
	if n, _ := d.UnreadCount("pen"); n != 2 {
		t.Fatalf("unread %d", n)
	}
	l, err := d.Notifications("pen", 50)
	if err != nil || len(l) != 2 || l[0].Event != "mentioned" || l[1].Text != "add a PoC" || l[1].TS == "" || l[1].Read {
		t.Fatalf("%+v %v", l, err)
	}
	// someone else's notification can't be marked
	if err := d.MarkRead("rev", id); err != ErrNotFound {
		t.Fatalf("mark other's: %v", err)
	}
	if err := d.MarkRead("pen", id); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.UnreadCount("pen"); n != 1 {
		t.Fatalf("unread %d", n)
	}
	if got, ok, _ := d.NotificationByID("pen", id); !ok || !got.Read {
		t.Fatalf("%+v", got)
	}
	d.MarkAllRead("pen")
	if n, _ := d.UnreadCount("pen"); n != 0 {
		t.Fatalf("unread %d", n)
	}
	if n, _ := d.UnreadCount("rev"); n != 1 {
		t.Fatalf("rev unread %d", n)
	}
}
