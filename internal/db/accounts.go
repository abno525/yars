package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/abno525/yars/internal/config"
)

// SessionIdle is how long a session lives without being used when the
// retention setting is 0 (Retention.SessionDays sets it otherwise).
const SessionIdle = 14 * 24 * time.Hour

// SessionMax is how long a session lives from its login at most, however
// much it is used: a cookie someone took stops working then.
const SessionMax = 30 * 24 * time.Hour

// SessionLeft is how long the session stored by hash holds from now if it
// is used now and not again: the idle time, or what is left of SessionMax
// when that is less (the session cookie's lifetime). Without such a session
// it is the idle time.
func (d *DB) SessionLeft(hash string) time.Duration {
	idle := d.sessionIdle()
	var created string
	if err := d.QueryRow("SELECT created FROM sessions WHERE hash = ?", hash).Scan(&created); err != nil {
		return idle
	}
	made, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return idle
	}
	return max(min(idle, SessionMax-d.now().Sub(made)), 0)
}

// Themes a user can choose ("" follows the system).
var Themes = []string{"", "light", "dark"}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ErrUserExists: AddUser found the username taken, as written or in another
// case of its ASCII letters.
var ErrUserExists = errors.New("user exists")

// userExists is an ErrUserExists with its own text for the reader.
type userExists string

func (e userExists) Error() string        { return string(e) }
func (e userExists) Is(target error) bool { return target == ErrUserExists }

func (d *DB) AddUser(u config.User) error {
	if !config.ValidRole(u.Role) {
		return fmt.Errorf("invalid role %q (want %s)", u.Role, strings.Join(config.Roles, ", "))
	}
	if !slices.Contains(Themes, u.Theme) {
		return fmt.Errorf("invalid theme %q", u.Theme)
	}
	return d.Tx(func(tx *Tx) error {
		// in the transaction (write transactions are one at a time): no two
		// requests both find the name free. lower() folds ASCII letters only,
		// as the email comparison does; Ä and ä stay two names.
		var taken string
		err := tx.QueryRow("SELECT username FROM users WHERE lower(username) = lower(?) ORDER BY username = ? DESC, username LIMIT 1", u.Username, u.Username).Scan(&taken)
		switch {
		case err == nil && taken == u.Username:
			return userExists(fmt.Sprintf("user %s already exists", u.Username))
		case err == nil:
			return userExists(fmt.Sprintf("user %s already exists as %s (only the case of letters differs)", u.Username, taken))
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		if err := neverDeleted(tx, u.Username); err != nil {
			return err
		}
		if err := emailFree(tx, u.Username, u.Email); err != nil {
			return err
		}
		_, err = tx.Exec("INSERT INTO users(username, email, role, password_hash, created, is_admin, disabled, theme, must_change, keys_off) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			u.Username, u.Email, u.Role, u.PasswordHash, d.stamp(), b2i(u.IsAdmin), b2i(u.Disabled), u.Theme, b2i(u.MustChange), b2i(u.KeysOff))
		return err
	})
}

// neverDeleted returns an ErrUserExists when an account of that name was
// deleted (DeleteUser), compared as AddUser compares names: the rows that
// name an account without a foreign key (sign-offs, chat, dismissals, the
// author of a finding) must not pass to another person.
func neverDeleted(tx *Tx, name string) error {
	var was string
	err := tx.QueryRow("SELECT username FROM deleted_users WHERE lower(username) = lower(?) ORDER BY username = ? DESC, username LIMIT 1", name, name).Scan(&was)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return userExists(fmt.Sprintf("user %s was deleted: the name stays taken", was))
}

// UsernameClashes lists the accounts whose usernames differ only in the
// case of ASCII letters, one entry per name ("Alice, alice"): accounts made
// before AddUser refused that.
func (d *DB) UsernameClashes() ([]string, error) {
	rows, err := d.Query(`SELECT group_concat(username, ', ') FROM (SELECT username FROM users ORDER BY username)
		GROUP BY lower(username) HAVING count(*) > 1 ORDER BY lower(username)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

const userCols = "username, email, role, password_hash, is_admin, disabled, theme, created, must_change, keys_off"

func scanUser(sc interface{ Scan(...any) error }) (config.User, error) {
	var u config.User
	err := sc.Scan(&u.Username, &u.Email, &u.Role, &u.PasswordHash, &u.IsAdmin, &u.Disabled, &u.Theme, &u.Created, &u.MustChange, &u.KeysOff)
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
		if err := neverDeleted(tx, u.Username); err != nil {
			return err
		}
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

// ErrEmailTaken: another account has that email already (git pushes are
// matched to accounts by the commit's author email).
var ErrEmailTaken = errors.New("email used by another account")

// commitEmail is the SQL for the email an account commits as (its own, or
// <username>@yars.local without one; see config.User.GitAuthor).
const commitEmail = "lower(CASE WHEN email = '' THEN username || '@yars.local' ELSE email END)"

// emailFree returns ErrEmailTaken when an account other than name commits
// as the email that name would commit as with email.
func emailFree(tx *Tx, name, email string) error {
	own := config.User{Username: name, Email: email}.GitAuthor().Email
	var other string
	err := tx.QueryRow("SELECT username FROM users WHERE username != ? AND "+commitEmail+" = lower(?) ORDER BY username LIMIT 1", name, own).Scan(&other)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: %s is the email of account %s", ErrEmailTaken, own, other)
}

// SetEmail changes the account's email (used for its git commits); one
// another account commits as is refused (ErrEmailTaken).
func (d *DB) SetEmail(name, email string) error {
	return d.Tx(func(tx *Tx) error {
		if err := emailFree(tx, name, email); err != nil {
			return err
		}
		res, err := tx.Exec("UPDATE users SET email = ? WHERE username = ?", email, name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("no user %s", name)
		}
		return nil
	})
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
// notification choices, team places and board read state. Its name is
// remembered and never given out again (AddUser, AddFirstUser).
func (d *DB) DeleteUser(name string) error {
	return d.Tx(func(tx *Tx) error {
		res, err := tx.Exec("DELETE FROM users WHERE username = ?", name)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("no user %s", name)
		}
		if _, err := tx.Exec("INSERT OR REPLACE INTO deleted_users(username, deleted) VALUES (?, ?)", name, tx.stamp()); err != nil {
			return err
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
	return d.setPassword(name, hash, "")
}

// ResetPassword is SetPassword with a temporary password an admin gave: the
// user must set a new one before anything else.
func (d *DB) ResetPassword(name, hash string) error {
	return d.setPassword(name, hash, ", must_change = 1")
}

// ChangePassword is the user's own new password: SetPassword that also
// ends the need to set one.
func (d *DB) ChangePassword(name, hash string) error {
	return d.setPassword(name, hash, ", must_change = 0")
}

func (d *DB) setPassword(name, hash, also string) error {
	return d.Tx(func(tx *Tx) error {
		res, err := tx.Exec("UPDATE users SET password_hash = ?"+also+" WHERE username = ?", hash, name)
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

// SetKeysOff stores whether the account's keyboard shortcuts are off.
func (d *DB) SetKeysOff(name string, off bool) error {
	// a preference, not content: no change counter
	res, err := d.Exec("UPDATE users SET keys_off = ? WHERE username = ?", b2i(off), name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fmt.Errorf("no user %s", name)
	}
	return nil
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

// TokensExpiring lists the tokens that expire after now and less than within
// after it, whose owner was not told yet (TokenNoted).
func (d *DB) TokensExpiring(now time.Time, within time.Duration) ([]TokenInfo, error) {
	l, err := d.tokens("WHERE expires != '' AND expiry_noted = ''")
	return slices.DeleteFunc(l, func(t TokenInfo) bool {
		exp, err := time.Parse(time.RFC3339, t.Expires)
		return err != nil || !exp.After(now) || exp.Sub(now) >= within
	}), err
}

// TokenNoted records that token id's owner was told it expires soon and
// stores note (nil: none, the owner wants it by email only) in the same
// transaction; false when that was already recorded or there is no such
// token, so one notice goes out per token, and none is lost. Like
// AddNotification it leaves the change counters alone: no content changed.
func (d *DB) TokenNoted(id int64, note *Notification) (bool, error) {
	tx, err := d.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback() // a no-op after the commit
	res, err := tx.Exec("UPDATE tokens SET expiry_noted = ? WHERE id = ? AND expiry_noted = ''", d.stamp(), id)
	if err != nil {
		return false, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return false, err
	}
	if note != nil {
		if _, err := tx.Exec("INSERT INTO notifications(username, event, eng, dir, fid, title, actor, text, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
			note.User, note.Event, note.Eng, note.Dir, note.Fid, note.Title, note.Actor, note.Text, d.stamp()); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

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
// session idle for longer than the retention's session days (SessionIdle
// when that is 0), or older than SessionMax, is deleted and rejected.
func (d *DB) SessionUser(hash string) (string, bool, error) {
	user, seen, found, good, err := d.session(hash)
	if err != nil || !found {
		return "", false, err
	}
	if !good {
		d.DeleteSession(hash)
		return "", false, nil
	}
	if d.now().Sub(seen) > time.Minute {
		d.Exec("UPDATE sessions SET last_seen = ? WHERE hash = ?", d.stamp(), hash)
	}
	return user, true, nil
}

// SessionAlive is SessionUser that writes nothing: it is no use of the
// session, so a caller that asks again and again (an open event stream)
// does not keep the session from going idle.
func (d *DB) SessionAlive(hash string) (string, bool, error) {
	user, _, found, good, err := d.session(hash)
	if err != nil || !found || !good {
		return "", false, err
	}
	return user, true, nil
}

// session reads the session stored by hash: its user, its last use, whether
// there is one (found) and whether it still holds now (good): used within
// the idle time, and made no longer than SessionMax ago.
func (d *DB) session(hash string) (user string, seen time.Time, found, good bool, err error) {
	var last, created string
	err = d.QueryRow("SELECT username, last_seen, created FROM sessions WHERE hash = ?", hash).Scan(&user, &last, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return "", seen, false, false, nil
	}
	if err != nil {
		return "", seen, false, false, err
	}
	seen, perr := time.Parse(time.RFC3339, last)
	made, cerr := time.Parse(time.RFC3339, created)
	good = perr == nil && cerr == nil && d.now().Sub(seen) <= d.sessionIdle() && d.now().Sub(made) <= SessionMax
	return user, seen, true, good, nil
}

func (d *DB) DeleteSession(hash string) error {
	_, err := d.Exec("DELETE FROM sessions WHERE hash = ?", hash)
	return err
}
