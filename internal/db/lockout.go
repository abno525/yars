package db

import (
	"database/sql"
	"errors"
	"time"
)

// Login lockout (D27): 5 failed attempts for a username, then 15 minutes in
// which none is tried. Counted per username, not per address, for names
// with no account too (so a lockout says nothing about whether one exists).
const (
	LoginTries   = 5
	LoginLockout = 15 * time.Minute
)

// loginRows bounds the table against sprayed usernames (pruneLogins); a
// variable so tests can lower it.
var loginRows = 10000

// LoginAttempt reserves an attempt for username before its password is
// checked, in one transaction, so parallel attempts can never get more than
// LoginTries guesses. It answers false (with the end of the lockout) while
// the name is locked out; otherwise the caller checks the password and then
// calls LoginDone. Failures older than LoginLockout no longer count.
func (d *DB) LoginAttempt(username string) (bool, time.Time, error) {
	now := d.now().UTC()
	ok, until := false, time.Time{}
	err := d.Tx(func(tx *Tx) error {
		var count int
		var last, lockedS string
		err := tx.QueryRow("SELECT count, last, locked_until FROM login_attempts WHERE username = ?", username).Scan(&count, &last, &lockedS)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if locked, perr := time.Parse(time.RFC3339, lockedS); perr == nil {
			if now.Before(locked) {
				until = locked
				return nil
			}
			count = 0 // the lockout is over: a fresh start
		}
		if t, perr := time.Parse(time.RFC3339, last); perr == nil && now.Sub(t) > LoginLockout {
			count = 0
		}
		count++
		lockedS = ""
		if count > LoginTries {
			// more attempts than tries in flight at once: this one waits
			until = now.Add(LoginLockout).Truncate(time.Second)
			lockedS = until.Format(time.RFC3339)
		}
		if _, err := tx.Exec(`INSERT INTO login_attempts(username, count, last, locked_until) VALUES (?, ?, ?, ?)
			ON CONFLICT(username) DO UPDATE SET count = excluded.count, last = excluded.last, locked_until = excluded.locked_until`,
			username, count, now.Format(time.RFC3339), lockedS); err != nil {
			return err
		}
		ok = lockedS == ""
		return pruneLogins(tx, now)
	})
	return ok, until, err
}

// pruneLogins drops rows that no longer count, then, over loginRows, the
// oldest rows that are not locked out: a lockout is never dropped early,
// however many other names are sprayed. Locked rows are not capped: each
// took LoginTries password checks to make and ends after LoginLockout, so
// the hashing rate bounds them (and a full table never refuses new names).
func pruneLogins(tx *Tx, now time.Time) error {
	old, ns := now.Add(-LoginLockout).Format(time.RFC3339), now.Format(time.RFC3339)
	if _, err := tx.Exec("DELETE FROM login_attempts WHERE last < ? AND locked_until < ?", old, ns); err != nil {
		return err
	}
	_, err := tx.Exec(`DELETE FROM login_attempts WHERE username IN (SELECT username FROM login_attempts WHERE locked_until < ?
		ORDER BY last DESC LIMIT -1 OFFSET ?)`, ns, loginRows)
	return err
}

// LoginDone ends an attempt LoginAttempt allowed: a success clears the
// name's count; a failure keeps it, and the one that reaches LoginTries
// locks the name out (lockedNow reports that this attempt did).
func (d *DB) LoginDone(username string, success bool) (lockedNow bool, until time.Time, err error) {
	now := d.now().UTC()
	err = d.Tx(func(tx *Tx) error {
		if success {
			_, err := tx.Exec("DELETE FROM login_attempts WHERE username = ?", username)
			return err
		}
		var count int
		var lockedS string
		err := tx.QueryRow("SELECT count, locked_until FROM login_attempts WHERE username = ?", username).Scan(&count, &lockedS)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil || count < LoginTries || lockedS != "" {
			return err
		}
		until = now.Add(LoginLockout).Truncate(time.Second)
		lockedNow = true
		_, err = tx.Exec("UPDATE login_attempts SET locked_until = ? WHERE username = ?", until.Format(time.RFC3339), username)
		return err
	})
	return lockedNow, until, err
}

// LockedUntil reports whether username is locked out now, and until when.
func (d *DB) LockedUntil(username string) (time.Time, bool, error) {
	var lockedS string
	err := d.QueryRow("SELECT locked_until FROM login_attempts WHERE username = ?", username).Scan(&lockedS)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, perr := time.Parse(time.RFC3339, lockedS)
	if perr != nil || !d.now().UTC().Before(t) {
		return time.Time{}, false, nil
	}
	return t, true, nil
}

// Lockouts lists the usernames locked out now, with when each lockout ends.
func (d *DB) Lockouts() (map[string]time.Time, error) {
	rows, err := d.Query("SELECT username, locked_until FROM login_attempts WHERE locked_until != ''")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := d.now().UTC()
	out := map[string]time.Time{}
	for rows.Next() {
		var u, s string
		if err := rows.Scan(&u, &s); err != nil {
			return nil, err
		}
		if t, perr := time.Parse(time.RFC3339, s); perr == nil && now.Before(t) {
			out[u] = t
		}
	}
	return out, rows.Err()
}

// ClearLockout ends username's lockout and count (an admin's doing).
func (d *DB) ClearLockout(username string) error {
	_, err := d.Exec("DELETE FROM login_attempts WHERE username = ?", username)
	return err
}
