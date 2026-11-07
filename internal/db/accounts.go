package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"yars/internal/config"
)

// SessionIdle is how long a session lives without being used.
const SessionIdle = 14 * 24 * time.Hour

// Themes a user can choose ("" follows the system).
var Themes = []string{"", "light", "dark"}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (d *DB) AddUser(u config.User) error {
	if !config.ValidRole(u.Role) {
		return fmt.Errorf("invalid role %q (want %s)", u.Role, strings.Join(config.Roles, ", "))
	}
	if !slices.Contains(Themes, u.Theme) {
		return fmt.Errorf("invalid theme %q", u.Theme)
	}
	if _, ok, err := d.User(u.Username); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("user %s already exists", u.Username)
	}
	return d.Tx(func(tx *Tx) error {
		_, err := tx.Exec("INSERT INTO users(username, email, role, password_hash, created, is_admin, disabled, theme) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			u.Username, u.Email, u.Role, u.PasswordHash, d.stamp(), b2i(u.IsAdmin), b2i(u.Disabled), u.Theme)
		return err
	})
}

const userCols = "username, email, role, password_hash, is_admin, disabled, theme, created"

func scanUser(sc interface{ Scan(...any) error }) (config.User, error) {
	var u config.User
	err := sc.Scan(&u.Username, &u.Email, &u.Role, &u.PasswordHash, &u.IsAdmin, &u.Disabled, &u.Theme, &u.Created)
	return u, err
}

// ErrNotFirst: AddFirstUser found accounts already.
var ErrNotFirst = errors.New("an account exists already")

// AddFirstUser adds u only while there is no account at all (first run);
// otherwise it returns ErrNotFirst. The check and the insert are one
// statement, so two first runs can't both succeed.
func (d *DB) AddFirstUser(u config.User) error {
	if !config.ValidRole(u.Role) {
		return fmt.Errorf("invalid role %q (want %s)", u.Role, strings.Join(config.Roles, ", "))
	}
	return d.Tx(func(tx *Tx) error {
		res, err := tx.Exec(`INSERT INTO users(username, email, role, password_hash, created, is_admin, disabled, theme)
			SELECT ?, ?, ?, ?, ?, ?, 0, '' WHERE NOT EXISTS (SELECT 1 FROM users)`,
			u.Username, u.Email, u.Role, u.PasswordHash, d.stamp(), b2i(u.IsAdmin))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return ErrNotFirst
		}
		return nil
	})
}

// UserCount is the number of accounts (disabled ones included).
func (d *DB) UserCount() (int, error) {
	var n int
	err := d.QueryRow("SELECT count(*) FROM users").Scan(&n)
	return n, err
}

// SetEmail changes the account's email (used for its git commits).
func (d *DB) SetEmail(name, email string) error {
	return d.update(name, "UPDATE users SET email = ? WHERE username = ?", email, name)
}

func (d *DB) User(name string) (config.User, bool, error) {
	u, err := scanUser(d.QueryRow("SELECT "+userCols+" FROM users WHERE username = ?", name))
	if errors.Is(err, sql.ErrNoRows) {
		return config.User{}, false, nil
	}
	return u, err == nil, err
}

// Users returns all accounts sorted by username (disabled ones included).
func (d *DB) Users() ([]config.User, error) {
	rows, err := d.Query("SELECT " + userCols + " FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []config.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
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

// DeleteUser removes an account with its sessions, tokens, keys,
// notification choices, team places and board read state.
func (d *DB) DeleteUser(name string) error {
	return d.Tx(func(tx *Tx) error {
		res, err := tx.Exec("DELETE FROM users WHERE username = ?", name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("no user %s", name)
		}
		// no foreign key: a new account of the same name must not follow
		// the notes this one opened
		if _, err := tx.Exec("DELETE FROM board_seen WHERE username = ?", name); err != nil {
			return err
		}
		rows, err := tx.Query("DELETE FROM engagement_members WHERE username = ? RETURNING eng", name)
		if err != nil {
			return err
		}
		var engs []string
		for rows.Next() {
			var e string
			if err := rows.Scan(&e); err != nil {
				rows.Close()
				return err
			}
			engs = append(engs, e)
		}
		rows.Close()
		for _, e := range engs {
			tx.touch(e)
		}
		return rows.Err()
	})
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

// SetAdmin turns the admin flag on or off (the role is unchanged).
func (d *DB) SetAdmin(name string, on bool) error {
	return d.update(name, "UPDATE users SET is_admin = ? WHERE username = ?", b2i(on), name)
}

// SetDisabled disables (on) or re-enables an account. Disabling ends its
// sessions; its tokens stay stored but are refused while it is disabled.
func (d *DB) SetDisabled(name string, on bool) error {
	return d.Tx(func(tx *Tx) error {
		res, err := tx.Exec("UPDATE users SET disabled = ? WHERE username = ?", b2i(on), name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("no user %s", name)
		}
		if on {
			_, err = tx.Exec("DELETE FROM sessions WHERE username = ?", name)
		}
		return err
	})
}

// SetTheme stores the account's theme ("light", "dark" or "" for the system).
func (d *DB) SetTheme(name, theme string) error {
	if !slices.Contains(Themes, theme) {
		return fmt.Errorf("invalid theme %q", theme)
	}
	_, ok, err := d.User(name)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no user %s", name)
	}
	// a preference, not content: no change counter
	_, err = d.Exec("UPDATE users SET theme = ? WHERE username = ?", theme, name)
	return err
}

// Token kinds: where a token is accepted.
const (
	TokenMCP = "mcp" // the /mcp endpoint (Bearer)
	TokenGit = "git" // git over HTTP (Basic, as the password)
)

// Token scopes. ScopeAll (CLI and older tokens) allows everything the
// account may do; ScopeRead only reading; otherwise the listed actions
// (reading is always included).
const (
	ScopeAll  = "all"
	ScopeRead = "read"
)

// Actions a scoped token can be given.
var TokenActions = []string{"create", "edit", "comment", "status", "reviewers", "checks", "export"}

// TokenSpec is what a new token may do.
type TokenSpec struct {
	Name        string
	Kind        string   // TokenMCP or TokenGit
	Scopes      []string // [ScopeAll], [ScopeRead] or TokenActions
	Engagements []string // empty = every engagement, archived ones included
	Expires     string   // RFC 3339; "" = never
}

// TokenInfo is a stored API token (only its hash is kept).
type TokenInfo struct {
	ID                                int64
	User, Hash, Name, Kind            string
	Scopes, Engagements               []string
	Expires, LastUsed, Last4, Created string
}

// Allows reports whether the token may perform action ("read" or one of
// TokenActions).
func (t TokenInfo) Allows(action string) bool {
	if action == ScopeRead || slices.Contains(t.Scopes, ScopeAll) {
		return true
	}
	return slices.Contains(t.Scopes, action)
}

// ReadOnly reports whether the token may only read.
func (t TokenInfo) ReadOnly() bool {
	return !slices.ContainsFunc(t.Scopes, func(s string) bool { return s != ScopeRead })
}

// AllowsEng reports whether the token is valid for engagement eng.
func (t TokenInfo) AllowsEng(eng string) bool {
	return len(t.Engagements) == 0 || slices.Contains(t.Engagements, eng)
}

// Restricted reports whether the token is limited to some engagements.
func (t TokenInfo) Restricted() bool { return len(t.Engagements) > 0 }

// Valid reports whether the token has not expired at now.
func (t TokenInfo) Valid(now time.Time) bool {
	if t.Expires == "" {
		return true
	}
	exp, err := time.Parse(time.RFC3339, t.Expires)
	return err == nil && now.Before(exp)
}

func validSpec(s TokenSpec) error {
	if s.Kind != TokenMCP && s.Kind != TokenGit {
		return fmt.Errorf("invalid token kind %q (want mcp or git)", s.Kind)
	}
	if len(s.Scopes) == 0 {
		return errors.New("a token needs a scope")
	}
	for _, sc := range s.Scopes {
		if (sc == ScopeAll || sc == ScopeRead) && len(s.Scopes) != 1 {
			return fmt.Errorf("scope %s stands alone", sc)
		}
		if sc != ScopeAll && sc != ScopeRead && !slices.Contains(TokenActions, sc) {
			return fmt.Errorf("invalid token scope %q", sc)
		}
	}
	if s.Expires != "" {
		if _, err := time.Parse(time.RFC3339, s.Expires); err != nil {
			return fmt.Errorf("invalid expiry %q", s.Expires)
		}
	}
	return nil
}

// scopesJSON stores ScopeAll and ScopeRead as a JSON string, actions as a
// JSON list.
func scopesJSON(sc []string) string {
	var b []byte
	if len(sc) == 1 && (sc[0] == ScopeAll || sc[0] == ScopeRead) {
		b, _ = json.Marshal(sc[0])
	} else {
		b, _ = json.Marshal(sc)
	}
	return string(b)
}

func parseScopes(s string) []string {
	var one string
	if json.Unmarshal([]byte(s), &one) == nil {
		return []string{one}
	}
	var list []string
	json.Unmarshal([]byte(s), &list)
	return list
}

// CreateToken stores a new token by its hash and key ending and returns its id.
func (d *DB) CreateToken(user, hash, last4 string, s TokenSpec) (int64, error) {
	if err := validSpec(s); err != nil {
		return 0, err
	}
	engs := s.Engagements
	if engs == nil {
		engs = []string{}
	}
	eb, _ := json.Marshal(engs)
	var id int64
	err := d.Tx(func(tx *Tx) error {
		err := tx.QueryRow(`INSERT INTO tokens(hash, username, name, kind, scopes, engagements, expires, last4, created)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			hash, user, s.Name, s.Kind, scopesJSON(s.Scopes), string(eb), s.Expires, last4, d.stamp()).Scan(&id)
		if err != nil && strings.Contains(err.Error(), "FOREIGN KEY") {
			return fmt.Errorf("no user %s", user)
		}
		return err
	})
	return id, err
}

// AddToken stores a token with every right for the MCP endpoint (yars token
// add, tokens.yaml from before the database).
func (d *DB) AddToken(user, hash string) error {
	last4 := ""
	if len(hash) >= 4 {
		last4 = hash[len(hash)-4:]
	}
	_, err := d.CreateToken(user, hash, last4, TokenSpec{Kind: TokenMCP, Scopes: []string{ScopeAll}})
	return err
}

const tokenCols = "id, username, hash, name, kind, scopes, engagements, expires, last_used, last4, created"

func scanToken(sc interface{ Scan(...any) error }) (TokenInfo, error) {
	var t TokenInfo
	var scopes, engs string
	err := sc.Scan(&t.ID, &t.User, &t.Hash, &t.Name, &t.Kind, &scopes, &engs, &t.Expires, &t.LastUsed, &t.Last4, &t.Created)
	t.Scopes = parseScopes(scopes)
	json.Unmarshal([]byte(engs), &t.Engagements)
	if len(t.Engagements) == 0 {
		t.Engagements = nil
	}
	return t, err
}

// TokenByHash looks a token up by its hash.
func (d *DB) TokenByHash(hash string) (TokenInfo, bool, error) {
	t, err := scanToken(d.QueryRow("SELECT "+tokenCols+" FROM tokens WHERE hash = ?", hash))
	if errors.Is(err, sql.ErrNoRows) {
		return TokenInfo{}, false, nil
	}
	return t, err == nil, err
}

func (d *DB) TokenUser(hash string) (string, bool, error) {
	t, ok, err := d.TokenByHash(hash)
	return t.User, ok, err
}

// TokenUsed records that token id was used now; within a minute of the
// last record nothing is written.
func (d *DB) TokenUsed(id int64) error {
	cutoff := d.now().Add(-time.Minute).UTC().Format(time.RFC3339)
	_, err := d.Exec("UPDATE tokens SET last_used = ? WHERE id = ? AND last_used <= ?", d.stamp(), id, cutoff)
	return err
}

// RevokeToken deletes token id; owner "" revokes anyone's (an admin), else
// only owner's own.
func (d *DB) RevokeToken(id int64, owner string) error {
	return d.Tx(func(tx *Tx) error {
		res, err := tx.Exec("DELETE FROM tokens WHERE id = ? AND (? = '' OR username = ?)", id, owner, owner)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("no token %d", id)
		}
		return nil
	})
}

func (d *DB) RevokeTokens(user string) error {
	return d.Tx(func(tx *Tx) error {
		_, err := tx.Exec("DELETE FROM tokens WHERE username = ?", user)
		return err
	})
}

func (d *DB) tokens(where string, args ...any) ([]TokenInfo, error) {
	rows, err := d.Query("SELECT "+tokenCols+" FROM tokens "+where+" ORDER BY username, created, id", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenInfo
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Tokens lists every token.
func (d *DB) Tokens() ([]TokenInfo, error) { return d.tokens("") }

// UserTokens lists one account's tokens.
func (d *DB) UserTokens(user string) ([]TokenInfo, error) {
	return d.tokens("WHERE username = ?", user)
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
