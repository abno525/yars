package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// Webhook is an outbound webhook: events matching Events are POSTed to URL,
// signed with the secret (stored encrypted; Last4 is its ending).
type Webhook struct {
	ID                 int64
	URL                string
	Events             []string
	SecretEnc, Last4   string
	Enabled            bool
	Created, CreatedBy string
}

// Delivery states.
const (
	DeliveryPending = "pending"
	DeliveryOK      = "ok"
	DeliveryFailed  = "failed" // gave up
)

// Delivery is one event queued for a webhook, with its latest try.
type Delivery struct {
	ID, HookID       int64
	Event, Payload   string
	Created, NextAt  string
	State            string
	Attempts, Status int
	Error, Finished  string
}

const hookCols = "id, url, events, secret_enc, last4, enabled, created, created_by"

func scanHook(sc interface{ Scan(...any) error }) (Webhook, error) {
	var h Webhook
	var ev string
	if err := sc.Scan(&h.ID, &h.URL, &ev, &h.SecretEnc, &h.Last4, &h.Enabled, &h.Created, &h.CreatedBy); err != nil {
		return h, err
	}
	json.Unmarshal([]byte(ev), &h.Events)
	return h, nil
}

func eventsJSON(ev []string) string {
	if ev == nil {
		ev = []string{}
	}
	b, _ := json.Marshal(ev)
	return string(b)
}

// AddWebhook stores a webhook and returns its id.
func (d *DB) AddWebhook(h Webhook) (int64, error) {
	res, err := d.Exec("INSERT INTO webhooks(url, events, secret_enc, last4, enabled, created, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
		h.URL, eventsJSON(h.Events), h.SecretEnc, h.Last4, b2i(h.Enabled), d.stamp(), h.CreatedBy)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) hooks(where string, args ...any) ([]Webhook, error) {
	rows, err := d.Query("SELECT "+hookCols+" FROM webhooks "+where+" ORDER BY id", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Webhook
	for rows.Next() {
		h, err := scanHook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Webhooks lists every webhook, oldest first.
func (d *DB) Webhooks() ([]Webhook, error) { return d.hooks("") }

// HooksFor lists the enabled webhooks that take event.
func (d *DB) HooksFor(event string) ([]Webhook, error) {
	all, err := d.hooks("WHERE enabled = 1")
	if err != nil {
		return nil, err
	}
	var out []Webhook
	for _, h := range all {
		if slices.Contains(h.Events, event) {
			out = append(out, h)
		}
	}
	return out, nil
}

// WebhookByID returns one webhook.
func (d *DB) WebhookByID(id int64) (Webhook, bool, error) {
	h, err := scanHook(d.QueryRow("SELECT "+hookCols+" FROM webhooks WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return h, false, nil
	}
	return h, err == nil, err
}

func (d *DB) hookUpdate(q string, args ...any) error {
	res, err := d.Exec(q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateWebhook changes a webhook's URL, events and switch (not its secret).
func (d *DB) UpdateWebhook(id int64, url string, events []string, enabled bool) error {
	return d.hookUpdate("UPDATE webhooks SET url = ?, events = ?, enabled = ? WHERE id = ?", url, eventsJSON(events), b2i(enabled), id)
}

// SetWebhookEnabled turns a webhook on or off.
func (d *DB) SetWebhookEnabled(id int64, on bool) error {
	return d.hookUpdate("UPDATE webhooks SET enabled = ? WHERE id = ?", b2i(on), id)
}

// DeleteWebhook removes a webhook and its deliveries.
func (d *DB) DeleteWebhook(id int64) error {
	return d.hookUpdate("DELETE FROM webhooks WHERE id = ?", id)
}

func stampAt(t time.Time) string { return t.UTC().Format(time.RFC3339) }

const deliveryCols = "id, hook_id, event, payload, created, next_at, state, attempts, status, error, finished"

func scanDelivery(sc interface{ Scan(...any) error }) (Delivery, error) {
	var x Delivery
	err := sc.Scan(&x.ID, &x.HookID, &x.Event, &x.Payload, &x.Created, &x.NextAt, &x.State, &x.Attempts, &x.Status, &x.Error, &x.Finished)
	return x, err
}

func (d *DB) deliveries(q string, args ...any) ([]Delivery, error) {
	rows, err := d.Query("SELECT "+deliveryCols+" FROM webhook_deliveries "+q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Delivery
	for rows.Next() {
		x, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// EnqueueDelivery queues payload for webhook hook, first tried at at.
func (d *DB) EnqueueDelivery(hook int64, event, payload string, at time.Time) (int64, error) {
	res, err := d.Exec("INSERT INTO webhook_deliveries(hook_id, event, payload, created, next_at) VALUES (?, ?, ?, ?, ?)",
		hook, event, payload, stampAt(at), stampAt(at))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DueDeliveries lists pending deliveries whose next try is due at now,
// oldest first.
func (d *DB) DueDeliveries(now time.Time, limit int) ([]Delivery, error) {
	return d.deliveries("WHERE state = ? AND next_at <= ? ORDER BY next_at, id LIMIT ?", DeliveryPending, stampAt(now), limit)
}

// FinishAttempt records a try of delivery id: status is the HTTP status (0
// = no answer), errText "" means it was delivered. A failed try is retried
// at next; a zero next gives up.
func (d *DB) FinishAttempt(id int64, status int, errText string, next, now time.Time) error {
	state, nextAt, finished := DeliveryPending, "", ""
	switch {
	case errText == "":
		state, finished = DeliveryOK, stampAt(now)
	case next.IsZero():
		state, finished = DeliveryFailed, stampAt(now)
	default:
		nextAt = stampAt(next)
	}
	return d.hookUpdate(`UPDATE webhook_deliveries SET state = ?, attempts = attempts + 1, status = ?, error = ?, finished = ?,
		next_at = CASE WHEN ? = '' THEN next_at ELSE ? END WHERE id = ?`, state, status, errText, finished, nextAt, nextAt, id)
}

// Delivery returns one delivery.
func (d *DB) Delivery(id int64) (Delivery, error) {
	x, err := scanDelivery(d.QueryRow("SELECT "+deliveryCols+" FROM webhook_deliveries WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return x, ErrNotFound
	}
	return x, err
}

// Deliveries lists a webhook's newest deliveries first.
func (d *DB) Deliveries(hook int64, limit int) ([]Delivery, error) {
	return d.deliveries("WHERE hook_id = ? ORDER BY id DESC LIMIT ?", hook, limit)
}

// LastDeliveries returns each webhook's newest delivery.
func (d *DB) LastDeliveries() (map[int64]Delivery, error) {
	l, err := d.deliveries("WHERE id IN (SELECT MAX(id) FROM webhook_deliveries GROUP BY hook_id)")
	if err != nil {
		return nil, err
	}
	out := map[int64]Delivery{}
	for _, x := range l {
		out[x.HookID] = x
	}
	return out, nil
}

// Redeliver queues a new copy of delivery id, due at now.
func (d *DB) Redeliver(id int64, now time.Time) (int64, error) {
	x, err := d.Delivery(id)
	if err != nil {
		return 0, err
	}
	return d.EnqueueDelivery(x.HookID, x.Event, x.Payload, now)
}

// Notification is one entry of a user's in-app notification list.
type Notification struct {
	ID                                int64
	User, Event, Eng, Dir, Fid, Title string
	Actor, Text, TS                   string
	Read                              bool
}

const noteCols = "id, username, event, eng, dir, fid, title, actor, text, ts, read"

func scanNote(sc interface{ Scan(...any) error }) (Notification, error) {
	var n Notification
	err := sc.Scan(&n.ID, &n.User, &n.Event, &n.Eng, &n.Dir, &n.Fid, &n.Title, &n.Actor, &n.Text, &n.TS, &n.Read)
	return n, err
}

// AddNotification stores a notification for n.User (TS is set now).
func (d *DB) AddNotification(n Notification) (int64, error) {
	res, err := d.Exec("INSERT INTO notifications(username, event, eng, dir, fid, title, actor, text, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		n.User, n.Event, n.Eng, n.Dir, n.Fid, n.Title, n.Actor, n.Text, d.stamp())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Notifications lists user's newest notifications first.
func (d *DB) Notifications(user string, limit int) ([]Notification, error) {
	rows, err := d.Query("SELECT "+noteCols+" FROM notifications WHERE username = ? ORDER BY id DESC LIMIT ?", user, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		n, err := scanNote(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// NotificationByID returns one of user's notifications.
func (d *DB) NotificationByID(user string, id int64) (Notification, bool, error) {
	n, err := scanNote(d.QueryRow("SELECT "+noteCols+" FROM notifications WHERE username = ? AND id = ?", user, id))
	if errors.Is(err, sql.ErrNoRows) {
		return n, false, nil
	}
	return n, err == nil, err
}

// UnreadCount is how many of user's notifications are unread.
func (d *DB) UnreadCount(user string) (int, error) {
	var n int
	err := d.QueryRow("SELECT COUNT(*) FROM notifications WHERE username = ? AND read = 0", user).Scan(&n)
	return n, err
}

// MarkRead marks one of user's notifications read (ErrNotFound for anyone
// else's).
func (d *DB) MarkRead(user string, id int64) error {
	res, err := d.Exec("UPDATE notifications SET read = 1 WHERE username = ? AND id = ?", user, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkAllRead marks every notification of user read.
func (d *DB) MarkAllRead(user string) error {
	_, err := d.Exec("UPDATE notifications SET read = 1 WHERE username = ? AND read = 0", user)
	return err
}
