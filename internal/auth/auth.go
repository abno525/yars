// Package auth implements local accounts with in-memory sessions.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sort"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"yars/internal/config"
)

const CookieName = "yars_session"

type ctxKey struct{}

type Auth struct {
	mu       sync.Mutex
	users    map[string]config.User
	sessions map[string]string // token -> username
	dummy    []byte
}

func New(users []config.User) *Auth {
	a := &Auth{users: map[string]config.User{}, sessions: map[string]string{}}
	for _, u := range users {
		a.users[u.Username] = u
	}
	a.dummy, _ = bcrypt.GenerateFromPassword([]byte("dummy"), 12)
	return a
}

// Users returns all accounts sorted by username.
func (a *Auth) Users() []config.User {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]config.User, 0, len(a.users))
	for _, u := range a.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

func HashPassword(pw string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	return string(h), err
}

// Login checks credentials and returns a new session token.
func (a *Auth) Login(username, pw string) (string, bool) {
	a.mu.Lock()
	u, ok := a.users[username]
	a.mu.Unlock()
	hash := a.dummy
	if ok {
		hash = []byte(u.PasswordHash)
	}
	// Always run bcrypt so unknown users take as long as wrong passwords.
	if bcrypt.CompareHashAndPassword(hash, []byte(pw)) != nil || !ok {
		return "", false
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", false
	}
	tok := hex.EncodeToString(b)
	a.mu.Lock()
	a.sessions[tok] = username
	a.mu.Unlock()
	return tok, true
}

func (a *Auth) Logout(token string) {
	a.mu.Lock()
	delete(a.sessions, token)
	a.mu.Unlock()
}

func (a *Auth) User(r *http.Request) (config.User, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return config.User{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	name, ok := a.sessions[c.Value]
	if !ok {
		return config.User{}, false
	}
	u, ok := a.users[name]
	return u, ok
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
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
}
