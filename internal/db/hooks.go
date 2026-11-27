package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
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
	// Failures is how many of its deliveries were given up in a row.
	Failures int
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

const hookCols = "id, url, events, secret_enc, last4, enabled, created, created_by, failures"

func scanHook(sc interface{ Scan(...any) error }) (Webhook, error) {
	var h Webhook
	var ev string
	if err := sc.Scan(&h.ID, &h.URL, &ev, &h.SecretEnc, &h.Last4, &h.Enabled, &h.Created, &h.CreatedBy, &h.Failures); err != nil {
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
// Another URL, or switching it on, starts the count of failed deliveries
// again.
func (d *DB) UpdateWebhook(id int64, url string, events []string, enabled bool) error {
	return d.hookUpdate(`UPDATE webhooks SET failures = CASE WHEN url <> ? OR (enabled = 0 AND ? = 1) THEN 0 ELSE failures END,
		url = ?, events = ?, enabled = ? WHERE id = ?`, url, b2i(enabled), url, eventsJSON(events), b2i(enabled), id)
}

// SetWebhookEnabled turns a webhook on or off; on starts the count of failed
// deliveries again.
func (d *DB) SetWebhookEnabled(id int64, on bool) error {
	return d.hookUpdate("UPDATE webhooks SET enabled = ?, failures = CASE WHEN ? = 1 THEN 0 ELSE failures END WHERE id = ?", b2i(on), b2i(on), id)
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

// PendingDeliveries counts the deliveries waiting to be sent or tried again.
func (d *DB) PendingDeliveries() (int, error) {
	var n int
	err := d.QueryRow("SELECT count(*) FROM webhook_deliveries WHERE state = ?", DeliveryPending).Scan(&n)
	return n, err
}

// FinishAttempt records a try of delivery id: status is the HTTP status (0
// = no answer), errText "" means it was delivered. A failed try is retried
// at next; a zero next gives up.
func (d *DB) FinishAttempt(id int64, status int, errText string, next, now time.Time) error {
	_, err := finishAttempt(d.DB, id, status, errText, next, now)
	return err
}

// finishAttempt is FinishAttempt on ex; it returns the delivery's new state.
func finishAttempt(ex interface {
	Exec(string, ...any) (sql.Result, error)
}, id int64, status int, errText string, next, now time.Time) (string, error) {
	state, nextAt, finished := DeliveryPending, "", ""
	switch {
	case errText == "":
		state, finished = DeliveryOK, stampAt(now)
	case next.IsZero():
		state, finished = DeliveryFailed, stampAt(now)
	default:
		nextAt = stampAt(next)
	}
	res, err := ex.Exec(`UPDATE webhook_deliveries SET state = ?, attempts = attempts + 1, status = ?, error = ?, finished = ?,
		next_at = CASE WHEN ? = '' THEN next_at ELSE ? END WHERE id = ?`, state, status, errText, finished, nextAt, nextAt, id)
	if err != nil {
		return "", err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return "", ErrNotFound
	}
	return state, nil
}

// FinishCounted is FinishAttempt that keeps the webhook's count of
// deliveries given up in a row, in the same transaction: a delivered one
// sets the count to 0; a given-up one adds one when gaveUp counts it, and at
// limit turns an enabled webhook off. It returns whether this call turned
// the webhook off, and the webhook as it was read before that.
func (d *DB) FinishCounted(id int64, status int, errText string, next, now time.Time, gaveUp bool, limit int) (bool, Webhook, error) {
	tx, err := d.Begin()
	if err != nil {
		return false, Webhook{}, err
	}
	defer tx.Rollback()
	state, err := finishAttempt(tx, id, status, errText, next, now)
	if err != nil {
		return false, Webhook{}, err
	}
	h, err := scanHook(tx.QueryRow("SELECT "+hookCols+" FROM webhooks WHERE id = (SELECT hook_id FROM webhook_deliveries WHERE id = ?)", id))
	if errors.Is(err, sql.ErrNoRows) {
		return false, h, ErrNotFound
	}
	if err != nil {
		return false, h, err
	}
	off := false
	switch {
	case state == DeliveryOK && h.Failures != 0:
		h.Failures = 0
		_, err = tx.Exec("UPDATE webhooks SET failures = 0 WHERE id = ?", h.ID)
	case state == DeliveryFailed && gaveUp:
		h.Failures++
		off = h.Enabled && limit > 0 && h.Failures >= limit
		_, err = tx.Exec("UPDATE webhooks SET failures = ?, enabled = CASE WHEN ? = 1 THEN 0 ELSE enabled END WHERE id = ?", h.Failures, b2i(off), h.ID)
	}
	if err != nil {
		return false, h, err
	}
	return off, h, tx.Commit()
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

// Notification is one entry of a user's in-app notification list. Thread is
// the chat thread it is about (the id of the thread's first message), ""
// for a notice that is not about a message.
type Notification struct {
	ID                                int64
	User, Event, Eng, Dir, Fid, Title string
	Actor, Text, TS                   string
	Thread                            string
	// Ref is what a notice without a finding is about: a webhook's id, a
	// lead's id (L-001); "" otherwise.
	Ref  string
	Read bool
}

const noteCols = "id, username, event, eng, dir, fid, title, actor, text, ts, read, thread, ref"

func scanNote(sc interface{ Scan(...any) error }) (Notification, error) {
	var n Notification
	err := sc.Scan(&n.ID, &n.User, &n.Event, &n.Eng, &n.Dir, &n.Fid, &n.Title, &n.Actor, &n.Text, &n.TS, &n.Read, &n.Thread, &n.Ref)
	return n, err
}

// AddNotification stores a notification for n.User (TS is set now).
func (d *DB) AddNotification(n Notification) (int64, error) {
	res, err := d.Exec("INSERT INTO notifications(username, event, eng, dir, fid, title, actor, text, ts, thread, ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		n.User, n.Event, n.Eng, n.Dir, n.Fid, n.Title, n.Actor, n.Text, d.stamp(), n.Thread, n.Ref)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// MarkFindingRead marks user's unread notifications of the finding fid (its
// ID, F-001: a new title renames its folder) of eng read. Nothing is
// written when there is none, so opening a finding's page is a read of the
// database but for the first time after a notice.
func (d *DB) MarkFindingRead(user, eng, fid string) error {
	if eng == "" || fid == "" {
		return nil
	}
	var one int
	err := d.QueryRow("SELECT 1 FROM notifications WHERE username = ? AND read = 0 AND eng = ? AND fid = ? LIMIT 1", user, eng, fid).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = d.Exec("UPDATE notifications SET read = 1 WHERE username = ? AND read = 0 AND eng = ? AND fid = ?", user, eng, fid)
	return err
}

// Notifications lists user's newest notifications first.
func (d *DB) Notifications(user string, limit int) ([]Notification, error) {
	return d.notes("", user, limit)
}

// UnreadNotifications lists user's newest unread notifications first.
func (d *DB) UnreadNotifications(user string, limit int) ([]Notification, error) {
	return d.notes(" AND read = 0", user, limit)
}

// onTeams keeps notifications of engagements whose team their user is on
// (and those about no engagement).
const onTeams = " AND (eng = '' OR eng IN (SELECT m.eng FROM engagement_members m WHERE m.username = notifications.username))"

// NotificationsFor lists user's newest notifications first: all of them
// when all is set (directors and admins see every engagement), otherwise
// only those of engagements whose team user is on; unread keeps the unread
// ones. The filters apply before the limit.
func (d *DB) NotificationsFor(user string, all, unread bool, limit int) ([]Notification, error) {
	cond := ""
	if !all {
		cond += onTeams
	}
	if unread {
		cond += " AND read = 0"
	}
	return d.notes(cond, user, limit)
}

// NotificationPage lists user's notifications newest first as
// NotificationsFor does, limited to the engagements engs when given (then
// none about no engagement), older than the id before (0: from the newest),
// at most limit: a page that marking or adding notifications between two
// calls neither skips nor repeats (MCP list_notifications).
func (d *DB) NotificationPage(user string, all, unread bool, engs []string, before int64, limit int) ([]Notification, error) {
	cond, args := "", []any{user}
	if !all {
		cond += onTeams
	}
	if unread {
		cond += " AND read = 0"
	}
	if len(engs) > 0 {
		cond += " AND eng IN (?" + strings.Repeat(",?", len(engs)-1) + ")"
		for _, e := range engs {
			args = append(args, e)
		}
	}
	if before > 0 {
		cond += " AND id < ?"
		args = append(args, before)
	}
	rows, err := d.Query("SELECT "+noteCols+" FROM notifications WHERE username = ?"+cond+" ORDER BY id DESC LIMIT ?", append(args, limit)...)
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

// UnreadCountFor is UnreadCount limited like NotificationsFor.
func (d *DB) UnreadCountFor(user string, all bool) (int, error) {
	q := "SELECT COUNT(*) FROM notifications WHERE username = ? AND read = 0"
	if !all {
		q += onTeams
	}
	var n int
	err := d.QueryRow(q, user).Scan(&n)
	return n, err
}

// UnreadNotes lists user's newest unread notifications first, filtered like
// NotificationsFor, without the events in skip and the engagements in
// skipEngs, at most limit, and how many there are in all (the inbox's
// Notifications section).
func (d *DB) UnreadNotes(user string, all bool, skip, skipEngs []string, limit int) ([]Notification, int, error) {
	cond, args := unreadNotesCond(user, all, skip, skipEngs)
	var total int
	if err := d.QueryRow("SELECT COUNT(*) FROM notifications WHERE username = ?"+cond, args...).Scan(&total); err != nil || total == 0 {
		return nil, 0, err
	}
	rows, err := d.Query("SELECT "+noteCols+" FROM notifications WHERE username = ?"+cond+" ORDER BY id DESC LIMIT ?", append(args, limit)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		n, err := scanNote(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, n)
	}
	return out, total, rows.Err()
}

// MarkNotesRead marks read every notification UnreadNotes lists for the
// same filters (the inbox section's Mark all read).
func (d *DB) MarkNotesRead(user string, all bool, skip, skipEngs []string) error {
	cond, args := unreadNotesCond(user, all, skip, skipEngs)
	_, err := d.Exec("UPDATE notifications SET read = 1 WHERE username = ?"+cond, args...)
	return err
}

// unreadNotesCond is UnreadNotes' filter after "username = ?", and its
// arguments (the user first).
func unreadNotesCond(user string, all bool, skip, skipEngs []string) (string, []any) {
	cond, args := " AND read = 0", []any{user}
	if !all {
		cond += onTeams
	}
	for _, not := range []struct {
		col  string
		vals []string
	}{{"event", skip}, {"eng", skipEngs}} {
		if len(not.vals) == 0 {
			continue
		}
		cond += " AND " + not.col + " NOT IN (?" + strings.Repeat(",?", len(not.vals)-1) + ")"
		for _, v := range not.vals {
			args = append(args, v)
		}
	}
	return cond, args
}

func (d *DB) notes(cond, user string, limit int) ([]Notification, error) {
	rows, err := d.Query("SELECT "+noteCols+" FROM notifications WHERE username = ?"+cond+" ORDER BY id DESC LIMIT ?", user, limit)
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

// MarkReadIDs marks those of user's notifications read, in one statement
// (ids of someone else's are left alone).
func (d *DB) MarkReadIDs(user string, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	args := []any{user}
	for _, id := range ids {
		args = append(args, id)
	}
	_, err := d.Exec("UPDATE notifications SET read = 1 WHERE username = ? AND id IN (?"+strings.Repeat(",?", len(ids)-1)+")", args...)
	return err
}

// MarkAllReadIn marks user's notifications of the engagements engs read
// (every one when engs is empty).
func (d *DB) MarkAllReadIn(user string, engs []string) error {
	if len(engs) == 0 {
		return d.MarkAllRead(user)
	}
	args := []any{user}
	for _, e := range engs {
		args = append(args, e)
	}
	_, err := d.Exec("UPDATE notifications SET read = 1 WHERE username = ? AND read = 0 AND eng IN (?"+strings.Repeat(",?", len(engs)-1)+")", args...)
	return err
}
