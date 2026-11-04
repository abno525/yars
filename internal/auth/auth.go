// Package auth implements local accounts and sessions, stored in the YARS
// database. Accounts are read on every check, so changes made with the CLI
// (useradd, role, passwd, userdel) apply without a restart.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"yars/internal/config"
	"yars/internal/db"
)

const CookieName = "yars_session"

type ctxKey struct{}

type Auth struct {
	db    *db.DB
	dummy []byte
}

func New(d *db.DB) *Auth {
	a := &Auth{db: d}
	a.dummy, _ = bcrypt.GenerateFromPassword([]byte("dummy"), 12)
	return a
}

// Users returns all accounts sorted by username.
func (a *Auth) Users() []config.User {
	us, _ := a.db.Users()
	return us
}

// Lookup returns one account.
func (a *Auth) Lookup(name string) (config.User, bool) {
	u, ok, _ := a.db.User(name)
	return u, ok
}

func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(h), err
}

// hashSecret is how session and API tokens are stored: never in plain text.
func hashSecret(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

// Check verifies credentials without creating a session (git HTTP auth).
// Unknown users take as long as wrong passwords.
func (a *Auth) Check(username, pw string) (config.User, bool) {
	u, ok := a.Lookup(username)
	hash := a.dummy
	if ok {
		hash = []byte(u.PasswordHash)
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(pw)) != nil || !ok {
		return config.User{}, false
	}
	return u, true
}

// Login checks credentials and returns a new session token.
func (a *Auth) Login(username, pw string) (string, bool) {
	if _, ok := a.Check(username, pw); !ok {
		return "", false
	}
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
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	})
}

func UserFrom(ctx context.Context) config.User {
	u, _ := ctx.Value(ctxKey{}).(config.User)
	return u
}

// SetCookie writes the session cookie for token.
func SetCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(db.SessionIdle.Seconds())})
}

func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
}
