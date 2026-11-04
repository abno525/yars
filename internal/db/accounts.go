package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"yars/internal/config"
)

// SessionIdle is how long a session lives without being used.
const SessionIdle = 14 * 24 * time.Hour

func (d *DB) AddUser(u config.User) error {
	if !config.ValidRole(u.Role) {
		return fmt.Errorf("invalid role %q (want %s)", u.Role, strings.Join(config.Roles, ", "))
	}
	if _, ok, err := d.User(u.Username); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("user %s already exists", u.Username)
	}
	return d.Tx(func(tx *Tx) error {
		_, err := tx.Exec("INSERT INTO users(username, email, role, password_hash, created) VALUES (?, ?, ?, ?, ?)",
			u.Username, u.Email, u.Role, u.PasswordHash, d.stamp())
		return err
	})
}

func (d *DB) User(name string) (config.User, bool, error) {
	var u config.User
	err := d.QueryRow("SELECT username, email, role, password_hash FROM users WHERE username = ?", name).
		Scan(&u.Username, &u.Email, &u.Role, &u.PasswordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return config.User{}, false, nil
	}
	return u, err == nil, err
}

// Users returns all accounts sorted by username.
func (d *DB) Users() ([]config.User, error) {
	rows, err := d.Query("SELECT username, email, role, password_hash FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []config.User
	for rows.Next() {
		var u config.User
		if err := rows.Scan(&u.Username, &u.Email, &u.Role, &u.PasswordHash); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// update runs one statement that must change exactly one user row.
func (d *DB) update(name, q string, args ...any) error {
	return d.Tx(func(tx *Tx) error {
		res, err := tx.Exec(q, args...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("no user %s", name)
		}
		return nil
	})
}

func (d *DB) DeleteUser(name string) error {
	return d.update(name, "DELETE FROM users WHERE username = ?", name)
}

// SetPassword changes the password and ends every session of the account
// (a reset after a compromise must lock the old cookies out). API tokens
// are kept; revoke them separately.
func (d *DB) SetPassword(name, hash string) error {
	return d.Tx(func(tx *Tx) error {
		res, err := tx.Exec("UPDATE users SET password_hash = ? WHERE username = ?", hash, name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("no user %s", name)
		}
		_, err = tx.Exec("DELETE FROM sessions WHERE username = ?", name)
		return err
	})
}

func (d *DB) SetRole(name, role string) error {
	if !config.ValidRole(role) {
		return fmt.Errorf("invalid role %q (want %s)", role, strings.Join(config.Roles, ", "))
	}
	return d.update(name, "UPDATE users SET role = ? WHERE username = ?", role, name)
}

// TokenInfo is a stored API token (only its hash is kept).
type TokenInfo struct{ User, Hash, Created string }

func (d *DB) AddToken(user, hash string) error {
	return d.Tx(func(tx *Tx) error {
		_, err := tx.Exec("INSERT INTO tokens(hash, username, created) VALUES (?, ?, ?)", hash, user, d.stamp())
		if err != nil && strings.Contains(err.Error(), "FOREIGN KEY") {
			return fmt.Errorf("no user %s", user)
		}
		return err
	})
}

func (d *DB) TokenUser(hash string) (string, bool, error) {
	var u string
	err := d.QueryRow("SELECT username FROM tokens WHERE hash = ?", hash).Scan(&u)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return u, err == nil, err
}

func (d *DB) RevokeTokens(user string) error {
	return d.Tx(func(tx *Tx) error {
		_, err := tx.Exec("DELETE FROM tokens WHERE username = ?", user)
		return err
	})
}

func (d *DB) Tokens() ([]TokenInfo, error) {
	rows, err := d.Query("SELECT username, hash, created FROM tokens ORDER BY username, created")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenInfo
	for rows.Next() {
		var t TokenInfo
		if err := rows.Scan(&t.User, &t.Hash, &t.Created); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Sessions are stored by the hash of their cookie token. They don't bump the
// change counter: logins are not content or workflow changes.

func (d *DB) CreateSession(hash, user string) error {
	_, err := d.Exec("INSERT INTO sessions(hash, username, created, last_seen) VALUES (?, ?, ?, ?)", hash, user, d.stamp(), d.stamp())
	return err
}

// SessionUser returns the session's user and refreshes its last use; a
// session idle for longer than SessionIdle is deleted and rejected.
func (d *DB) SessionUser(hash string) (string, bool, error) {
	var user, seen string
	err := d.QueryRow("SELECT username, last_seen FROM sessions WHERE hash = ?", hash).Scan(&user, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	t, err := time.Parse(time.RFC3339, seen)
	if err != nil || d.now().Sub(t) > SessionIdle {
		d.DeleteSession(hash)
		return "", false, nil
	}
	if d.now().Sub(t) > time.Minute {
		d.Exec("UPDATE sessions SET last_seen = ? WHERE hash = ?", d.stamp(), hash)
	}
	return user, true, nil
}

func (d *DB) DeleteSession(hash string) error {
	_, err := d.Exec("DELETE FROM sessions WHERE hash = ?", hash)
	return err
}
