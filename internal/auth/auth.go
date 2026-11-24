// Package auth implements local accounts and sessions, stored in the YARS
// database. Accounts are read on every check, so changes made with the CLI
// (useradd, role, passwd, userdel) apply without a restart.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"yars/internal/config"
	"yars/internal/db"
)

const CookieName = "yars_session"

type ctxKey struct{}

type Auth struct {
	// Secure marks the session cookie Secure (the site is served over HTTPS).
	Secure bool

	db    *db.DB
	dummy []byte
}

// defaultCost is the bcrypt cost of every stored password and of the dummy
// hash. Nothing outside this package can change cost: no flag, env var,
// config or exported setter. Only this package's own tests lower it.
const defaultCost = 12

var cost = defaultCost

// The dummy hash is the same for every Auth, so it is made once per process.
var (
	dummyOnce sync.Once
	dummyHash []byte
)

func New(d *db.DB) *Auth {
	dummyOnce.Do(func() { dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy"), cost) })
	return &Auth{db: d, dummy: dummyHash}
}

// Users returns all accounts sorted by username.
func (a *Auth) Users() []config.User {
	us, _ := a.db.Users()
	return us
}

// Lookup returns one active account (a disabled one is not found).
func (a *Auth) Lookup(name string) (config.User, bool) {
	u, ok, _ := a.db.User(name)
	if !ok || u.Disabled {
		return config.User{}, false
	}
	return u, true
}

// MinPassword is the shortest password YARS accepts, in characters, and
// MaxPasswordBytes the longest, in bytes (bcrypt's limit): on the website
// (setup, Admin › Users, a password change) and from yars useradd and yars
// passwd.
const (
	MinPassword      = 10
	MaxPasswordBytes = 72
)

// PasswordProblem says what is wrong with pw as a new password ("" = fine),
// for the reader to prefix: "at least 10 characters" or "at most 72 bytes".
func PasswordProblem(pw string) string {
	switch {
	case utf8.RuneCountInString(pw) < MinPassword:
		return fmt.Sprintf("at least %d characters", MinPassword)
	case len(pw) > MaxPasswordBytes:
		return fmt.Sprintf("at most %d bytes", MaxPasswordBytes)
	}
	return ""
}

func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), cost)
	return string(h), err
}

// hashSecret is how session and API tokens are stored: never in plain text.
func hashSecret(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// Check verifies credentials without creating a session (git HTTP auth, a
// current password). Unknown users take as long as wrong passwords. A
// temporary password (MustChange) is good for logging in to set a new one
// only, so Check refuses it.
func (a *Auth) Check(username, pw string) (config.User, bool) {
	u, err := a.CheckErr(username, pw)
	return u, err == nil
}

// ErrMustChange refuses a good password or token of an account whose
// temporary password is not replaced yet: it says what to do.
var ErrMustChange = errors.New("set a new password first (log in on the website)")

// ErrRefused is every other refusal of credentials.
var ErrRefused = errors.New("authentication required")

// CheckErr is Check with the reason of a refusal (ErrMustChange or
// ErrRefused).
func (a *Auth) CheckErr(username, pw string) (config.User, error) {
	u, ok := a.verify(username, pw)
	if !ok {
		return config.User{}, ErrRefused
	}
	if u.MustChange {
		return config.User{}, ErrMustChange
	}
	return u, nil
}

// Verify reports whether pw is the account's password now (a temporary one
// included), for a signed-in user's own checks: it is no login attempt.
func (a *Auth) Verify(username, pw string) bool {
	u, ok := a.Lookup(username)
	return ok && bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(pw)) == nil
}

// verify is every password login (web, git over HTTP): an attempt of the
// username is reserved first, so a name locked out (D27: 5 failures, then
// 15 minutes) gets no guess at all, whether or not it has an account. A
// success clears the count; the failure that reaches the limit starts the
// lockout and goes to the audit log.
func (a *Auth) verify(username, pw string) (config.User, bool) {
	ok, _, err := a.db.LoginAttempt(username)
	if err != nil || !ok {
		return config.User{}, false
	}
	u, ok := a.Lookup(username)
	hash := a.dummy
	if ok {
		hash = []byte(u.PasswordHash)
	}
	good := bcrypt.CompareHashAndPassword(hash, []byte(pw)) == nil && ok
	if locked, until, err := a.db.LoginDone(username, good); err == nil && locked {
		a.db.Audit(username, "login.lockout", username, until.Format(time.RFC3339))
	}
	if !good {
		return config.User{}, false
	}
	return u, true
}

// LockedUntil reports whether username is locked out of password logins
// now, and until when.
func (a *Auth) LockedUntil(username string) (time.Time, bool) {
	t, ok, _ := a.db.LockedUntil(username)
	return t, ok
}

// Login checks credentials and returns a new session token. Successes and
// failures go to the audit log. A temporary password logs in: the session
// may only set a new password (web: the set-password page).
func (a *Auth) Login(username, pw string) (string, bool) {
	if _, ok := a.verify(username, pw); !ok {
		a.db.AuditLoginFail(username)
		return "", false
	}
	a.db.Audit(username, "login", "", "")
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", false
	}
	tok := hex.EncodeToString(b)
	if err := a.db.CreateSession(hashSecret(tok), username); err != nil {
		return "", false
	}
	return tok, true
}

func (a *Auth) Logout(token string) { a.db.DeleteSession(hashSecret(token)) }

func (a *Auth) User(r *http.Request) (config.User, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return config.User{}, false
	}
	name, ok, _ := a.db.SessionUser(hashSecret(c.Value))
	if !ok {
		return config.User{}, false
	}
	return a.Lookup(name)
}

func (a *Auth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := a.User(r)
		if !ok {
			// htmx requests from an open page: the page keeps what was typed
			if r.Header.Get("HX-Request") == "true" {
				http.Error(w, "Session expired", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// a page load renews the cookie: an active session does not expire
		// SessionIdle after login (htmx requests from an open page do not)
		if r.Method == http.MethodGet && r.Header.Get("HX-Request") != "true" {
			if c, err := r.Cookie(CookieName); err == nil {
				a.SetCookie(w, c.Value)
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

func UserFrom(ctx context.Context) config.User {
	u, _ := ctx.Value(ctxKey{}).(config.User)
	return u
}

// SetCookie writes the session cookie for token (Secure over HTTPS).
func (a *Auth) SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: a.Secure, MaxAge: int(db.SessionIdle.Seconds())})
}

// ClearCookie removes the session cookie (with the attributes it was set with).
func (a *Auth) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: a.Secure})
}
