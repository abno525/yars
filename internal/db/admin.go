package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Server settings: values edited on the admin pages. They are settings,
// not content, so no change counter moves.

// SetSetting stores value under key; an empty value removes the key.
func (d *DB) SetSetting(key, value string) error {
	var err error
	if value == "" {
		_, err = d.Exec("DELETE FROM server_settings WHERE key = ?", key)
	} else {
		_, err = d.Exec(`INSERT INTO server_settings(key, value) VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	}
	return err
}

// Setting returns the value stored under key ("" when unset).
func (d *DB) Setting(key string) (string, error) {
	var v string
	err := d.QueryRow("SELECT value FROM server_settings WHERE key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// Settings returns every setting whose key starts with prefix.
func (d *DB) Settings(prefix string) (map[string]string, error) {
	rows, err := d.Query("SELECT key, value FROM server_settings WHERE substr(key, 1, ?) = ?", len(prefix), prefix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SessionInfo is one signed-in browser (the cookie itself is never stored).
type SessionInfo struct {
	ID                      int64
	User, Created, LastSeen string
}

// Sessions lists every session, most recently used first.
func (d *DB) Sessions() ([]SessionInfo, error) {
	rows, err := d.Query("SELECT rowid, username, created, last_seen FROM sessions ORDER BY last_seen DESC, rowid DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionInfo
	for rows.Next() {
		var s SessionInfo
		if err := rows.Scan(&s.ID, &s.User, &s.Created, &s.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteSessionID ends session id (as listed by Sessions).
func (d *DB) DeleteSessionID(id int64) error {
	res, err := d.Exec("DELETE FROM sessions WHERE rowid = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("no session %d", id)
	}
	return nil
}

// Snapshot writes a consistent copy of the database to path (VACUUM INTO);
// path must not exist yet.
func (d *DB) Snapshot(path string) error {
	_, err := d.Exec("VACUUM INTO ?", path)
	return err
}

// Size is the database's size in bytes (pages in use and free).
func (d *DB) Size() (int64, error) {
	var n int64
	err := d.QueryRow("SELECT p.page_count * s.page_size FROM pragma_page_count() p, pragma_page_size() s").Scan(&n)
	return n, err
}

// Check runs SQLite's quick integrity check ("ok" when sound).
func (d *DB) Check() (string, error) {
	var res string
	err := d.QueryRow("PRAGMA quick_check").Scan(&res)
	return res, err
}

// ChatCount is the number of chat messages (events included).
func (d *DB) ChatCount() (int, error) {
	var n int
	err := d.QueryRow("SELECT count(*) FROM chat").Scan(&n)
	return n, err
}

// Version reads the schema version of the open database.
func (d *DB) Version() (int, error) {
	var v int
	err := d.QueryRow("PRAGMA user_version").Scan(&v)
	return v, err
}

// AuditFilter selects audit entries: by actor, by action (the action or its
// group: "login" also matches "login.fail"), a page of them.
type AuditFilter struct {
	Actor, Action string
	Limit, Offset int
}

// AuditQuery returns one page of matching entries, newest first, and how
// many match in all.
func (d *DB) AuditQuery(f AuditFilter) ([]AuditEntry, int, error) {
	var where []string
	var args []any
	if f.Actor != "" {
		where, args = append(where, "actor = ?"), append(args, f.Actor)
	}
	if f.Action != "" {
		where = append(where, "(action = ? OR substr(action, 1, ?) = ?)")
		args = append(args, f.Action, len(f.Action)+1, f.Action+".")
	}
	w := ""
	if len(where) > 0 {
		w = " WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := d.QueryRow("SELECT count(*) FROM audit"+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	rows, err := d.Query("SELECT id, ts, actor, action, target, detail FROM audit"+w+" ORDER BY id DESC LIMIT ? OFFSET ?",
		append(args, f.Limit, max(f.Offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var a AuditEntry
		if err := rows.Scan(&a.ID, &a.TS, &a.Actor, &a.Action, &a.Target, &a.Detail); err != nil {
			return nil, 0, err
		}
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// AuditActors lists everyone who appears in the audit log, sorted. Names
// typed into failed logins before they were filed under FailedLoginActor
// are left out.
func (d *DB) AuditActors() ([]string, error) {
	rows, err := d.Query("SELECT DISTINCT actor FROM audit WHERE action != 'login.fail' OR actor = ? ORDER BY actor", FailedLoginActor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
