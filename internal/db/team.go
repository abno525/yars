package db

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Engagement teams: who works on an engagement. Directors and admins see
// every engagement whether or not they are on its team.

// AddMembers puts users on eng's team (already members are kept).
func (d *DB) AddMembers(eng string, users ...string) error {
	return d.TxFor(eng, func(tx *Tx) error { return tx.AddMembers(eng, users...) })
}

// AddMembers is AddMembers inside a transaction.
func (tx *Tx) AddMembers(eng string, users ...string) error {
	tx.touch(eng)
	for _, u := range users {
		if _, err := tx.Exec("INSERT OR IGNORE INTO engagement_members(eng, username) VALUES (?, ?)", eng, u); err != nil {
			return err
		}
	}
	return nil
}

// RemoveMember takes user off eng's team.
func (d *DB) RemoveMember(eng, user string) error {
	return d.TxFor(eng, func(tx *Tx) error {
		_, err := tx.Exec("DELETE FROM engagement_members WHERE eng = ? AND username = ?", eng, user)
		return err
	})
}

// Members lists eng's team, sorted.
func (d *DB) Members(eng string) ([]string, error) { return members(d, eng) }

// Members is Members inside a transaction.
func (tx *Tx) Members(eng string) ([]string, error) { return members(tx, eng) }

func members(q querier, eng string) ([]string, error) {
	rows, err := q.Query("SELECT username FROM engagement_members WHERE eng = ? ORDER BY username", eng)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// IsMember reports whether user is on eng's team.
func (d *DB) IsMember(eng, user string) (bool, error) {
	var n int
	err := d.QueryRow("SELECT count(*) FROM engagement_members WHERE eng = ? AND username = ?", eng, user).Scan(&n)
	return n > 0, err
}

// MemberOf returns the engagements whose team user is on.
func (d *DB) MemberOf(user string) (map[string]bool, error) {
	rows, err := d.Query("SELECT eng FROM engagement_members WHERE username = ?", user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, err
		}
		out[e] = true
	}
	return out, rows.Err()
}

// EngMeta is what the database knows about an engagement beyond its files.
type EngMeta struct {
	Archived               bool
	ArchivedAt, ArchivedBy string
}

// EngMeta returns eng's archive state.
func (d *DB) EngMeta(eng string) (EngMeta, error) {
	var m EngMeta
	err := d.QueryRow("SELECT archived_at, archived_by FROM engagement_meta WHERE eng = ?", eng).Scan(&m.ArchivedAt, &m.ArchivedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return EngMeta{}, nil
	}
	m.Archived = m.ArchivedAt != ""
	return m, err
}

// Archived reports, inside a transaction, whether eng is archived, so a
// write can't slip in next to an archive.
func (tx *Tx) Archived(eng string) (bool, error) {
	var at string
	err := tx.QueryRow("SELECT archived_at FROM engagement_meta WHERE eng = ?", eng).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return at != "", err
}

// ArchivedEngagements returns every archived engagement with its state.
func (d *DB) ArchivedEngagements() (map[string]EngMeta, error) {
	rows, err := d.Query("SELECT eng, archived_at, archived_by FROM engagement_meta WHERE archived_at != ''")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]EngMeta{}
	for rows.Next() {
		var e string
		m := EngMeta{Archived: true}
		if err := rows.Scan(&e, &m.ArchivedAt, &m.ArchivedBy); err != nil {
			return nil, err
		}
		out[e] = m
	}
	return out, rows.Err()
}

// Archive makes eng read-only, recording who did it and when.
func (d *DB) Archive(eng, by string) error {
	return d.TxFor(eng, func(tx *Tx) error {
		_, err := tx.Exec(`INSERT INTO engagement_meta(eng, archived_at, archived_by) VALUES (?, ?, ?)
			ON CONFLICT(eng) DO UPDATE SET archived_at = excluded.archived_at, archived_by = excluded.archived_by`, eng, d.stamp(), by)
		return err
	})
}

// Unarchive opens eng for changes again.
func (d *DB) Unarchive(eng string) error {
	return d.TxFor(eng, func(tx *Tx) error {
		_, err := tx.Exec("UPDATE engagement_meta SET archived_at = '', archived_by = '' WHERE eng = ?", eng)
		return err
	})
}

// AuditEntry is one line of the audit log.
type AuditEntry struct {
	ID                                int64
	TS, Actor, Action, Target, Detail string
}

// Audit appends to the audit log. It is not a content or workflow change,
// so no change counter moves.
func (d *DB) Audit(actor, action, target, detail string) error {
	_, err := d.Exec("INSERT INTO audit(ts, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)", d.stamp(), actor, action, target, detail)
	return err
}

// AuditLog returns the newest limit entries, newest first.
func (d *DB) AuditLog(limit int) ([]AuditEntry, error) {
	rows, err := d.Query("SELECT id, ts, actor, action, target, detail FROM audit ORDER BY id DESC LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.TS, &a.Actor, &a.Action, &a.Target, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Connection is a personal key for an outside service (stored encrypted).
type Connection struct{ Service, Created string }

// SetConnection stores (or replaces) user's encrypted key for service.
func (d *DB) SetConnection(user, service, secretEnc string) error {
	_, err := d.Exec(`INSERT INTO connections(username, service, secret_enc, created) VALUES (?, ?, ?, ?)
		ON CONFLICT(username, service) DO UPDATE SET secret_enc = excluded.secret_enc, created = excluded.created`,
		user, service, secretEnc, d.stamp())
	if err != nil && strings.Contains(err.Error(), "FOREIGN KEY") {
		return fmt.Errorf("no user %s", user)
	}
	return err
}

// Connection returns user's encrypted key for service.
func (d *DB) Connection(user, service string) (string, bool, error) {
	var enc string
	err := d.QueryRow("SELECT secret_enc FROM connections WHERE username = ? AND service = ?", user, service).Scan(&enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return enc, err == nil, err
}

// Connections lists user's connected services.
func (d *DB) Connections(user string) ([]Connection, error) {
	rows, err := d.Query("SELECT service, created FROM connections WHERE username = ? ORDER BY service", user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Connection
	for rows.Next() {
		var c Connection
		if err := rows.Scan(&c.Service, &c.Created); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteConnection removes user's key for service.
func (d *DB) DeleteConnection(user, service string) error {
	_, err := d.Exec("DELETE FROM connections WHERE username = ? AND service = ?", user, service)
	return err
}

// SetNotify turns delivery of event over channel on or off for user.
func (d *DB) SetNotify(user, event, channel string, on bool) error {
	var err error
	if on {
		_, err = d.Exec("INSERT OR IGNORE INTO notify_prefs(username, event, channel) VALUES (?, ?, ?)", user, event, channel)
	} else {
		_, err = d.Exec("DELETE FROM notify_prefs WHERE username = ? AND event = ? AND channel = ?", user, event, channel)
	}
	return err
}

// NotifyPrefs returns user's channels per event (sorted).
func (d *DB) NotifyPrefs(user string) (map[string][]string, error) {
	rows, err := d.Query("SELECT event, channel FROM notify_prefs WHERE username = ?", user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var e, c string
		if err := rows.Scan(&e, &c); err != nil {
			return nil, err
		}
		out[e] = append(out[e], c)
	}
	for _, v := range out {
		sort.Strings(v)
	}
	return out, rows.Err()
}
