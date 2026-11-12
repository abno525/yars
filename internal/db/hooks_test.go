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

// The inbox's notices: unread only, without the skipped events and
// engagements, the team filter as the bell's; the total is not capped.
func TestUnreadNotes(t *testing.T) {
	d := openTest(t)
	d.AddUser(config.User{Username: "pen", Role: "pentester"})
	d.AddMembers("acme", "pen")
	d.AddMembers("old", "pen")
	d.AddNotification(Notification{User: "pen", Event: "returned", Eng: "acme", Fid: "F-001", Text: "skipped event"})
	d.AddNotification(Notification{User: "pen", Event: "mentioned", Eng: "old", Fid: "F-001", Text: "skipped engagement"})
	d.AddNotification(Notification{User: "pen", Event: "mentioned", Eng: "other", Fid: "F-001", Text: "not on the team"})
	id, _ := d.AddNotification(Notification{User: "pen", Event: "approved", Eng: "acme", Fid: "F-002", Text: "read"})
	d.MarkRead("pen", id)
	d.AddNotification(Notification{User: "pen", Event: "token", Text: "no engagement"})
	d.AddNotification(Notification{User: "pen", Event: "approved", Eng: "acme", Fid: "F-003", Text: "newest"})
	l, total, err := d.UnreadNotes("pen", false, []string{"returned", "review"}, []string{"old"}, 1)
	if err != nil || total != 2 || len(l) != 1 || l[0].Text != "newest" {
		t.Fatalf("%d %+v %v", total, l, err)
	}
	if _, total, _ := d.UnreadNotes("pen", true, nil, nil, 50); total != 5 {
		t.Fatalf("all %d", total)
	}
	if l, total, err := d.UnreadNotes("rev", false, nil, nil, 50); err != nil || total != 0 || l != nil {
		t.Fatalf("none %d %+v %v", total, l, err)
	}
	// marking them read leaves the skipped and the other teams' ones
	if err := d.MarkNotesRead("pen", false, []string{"returned", "review"}, []string{"old"}); err != nil {
		t.Fatal(err)
	}
	if n, _ := d.UnreadCountFor("pen", true); n != 3 {
		t.Fatalf("unread after %d", n)
	}
}

// Listing and counting for someone who sees only their teams' engagements
// skip the others (filtered before the limit); notifications without an
// engagement always count.
func TestNotificationsForTeams(t *testing.T) {
	d := openTest(t)
	d.AddUser(config.User{Username: "pen", Role: "pentester"})
	d.AddMembers("acme", "pen")
	d.AddNotification(Notification{User: "pen", Event: "returned", Eng: "acme", Fid: "F-001", Text: "mine"})
	d.AddNotification(Notification{User: "pen", Event: "token", Text: "no engagement"})
	for range 5 {
		d.AddNotification(Notification{User: "pen", Event: "mentioned", Eng: "other", Fid: "F-002", Text: "not mine"})
	}
	if n, _ := d.UnreadCountFor("pen", false); n != 2 {
		t.Fatalf("team unread %d", n)
	}
	if n, _ := d.UnreadCountFor("pen", true); n != 7 {
		t.Fatalf("all unread %d", n)
	}
	l, err := d.NotificationsFor("pen", false, false, 2)
	if err != nil || len(l) != 2 || l[0].Text != "no engagement" || l[1].Text != "mine" {
		t.Fatalf("%+v %v", l, err)
	}
	if l, _ := d.NotificationsFor("pen", false, true, 50); len(l) != 2 {
		t.Fatalf("unread %+v", l)
	}
	if l, _ := d.NotificationsFor("pen", true, false, 50); len(l) != 7 {
		t.Fatalf("all %d", len(l))
	}
}

// Taking someone off a team deletes their notifications of that engagement
// in the same step; coming back does not bring them back.
func TestRemoveMemberDeletesNotifications(t *testing.T) {
	d := openTest(t)
	d.AddUser(config.User{Username: "pen", Role: "pentester"})
	d.AddUser(config.User{Username: "rev", Role: "reviewer"})
	d.AddMembers("acme", "pen", "rev")
	d.AddMembers("beta", "pen")
	d.AddNotification(Notification{User: "pen", Event: "returned", Eng: "acme", Fid: "F-001"})
	d.AddNotification(Notification{User: "pen", Event: "returned", Eng: "beta", Fid: "F-001"})
	d.AddNotification(Notification{User: "rev", Event: "review", Eng: "acme", Fid: "F-001"})
	if err := d.RemoveMember("acme", "pen"); err != nil {
		t.Fatal(err)
	}
	d.AddMembers("acme", "pen")
	if l, _ := d.Notifications("pen", 50); len(l) != 1 || l[0].Eng != "beta" {
		t.Fatalf("pen %+v", l)
	}
	if n, _ := d.UnreadCount("rev"); n != 1 {
		t.Fatalf("rev's notification went too: %d", n)
	}
}
