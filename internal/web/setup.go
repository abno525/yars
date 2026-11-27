package web

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/store"
)

// noUsers reports whether the database has no account yet (first run).
// Once one exists the answer is remembered (the web pages can't delete
// accounts, so first run never comes back while the server runs).
func (s *Server) noUsers() bool {
	if s.hasUsers.Load() || s.Store == nil || s.Store.DB() == nil {
		return false
	}
	n, err := s.Store.DB().UserCount()
	if err != nil || n > 0 {
		s.hasUsers.Store(err == nil)
		return false
	}
	return true
}

// NewSetupCode makes a setup code (Server.SetupCode): random, typeable,
// three groups of four letters and digits.
func NewSetupCode() string { return newTempPassword() }

// firstRun sends every request to /setup while there is no account (static
// files excepted, and the health probe, whose answer must not tell a new
// server from a set-up one).
func (s *Server) firstRun(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/setup" && r.URL.Path != "/healthz" && !strings.HasPrefix(r.URL.Path, "/static/") && s.noUsers() {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	if !s.noUsers() {
		http.NotFound(w, r)
		return
	}
	s.render(w, "setup.html", &page{Bare: true})
}

// newPasswordProblem checks a new password as every form does ("" = fine):
// its length (auth.PasswordProblem).
func newPasswordProblem(pw string) string {
	if p := auth.PasswordProblem(pw); p != "" {
		return "Password: " + p
	}
	return ""
}

// passwordProblem checks a new password typed twice ("" = fine).
func passwordProblem(pw, repeat string) string {
	switch {
	case newPasswordProblem(pw) != "":
		return newPasswordProblem(pw)
	case pw != repeat:
		return "Passwords differ"
	}
	return ""
}

// emailProblem checks an optional email address ("" = fine).
func emailProblem(email string) string {
	if email == "" {
		return ""
	}
	if a, err := mail.ParseAddress(email); err != nil || a.Address != email {
		return "Email: not an address"
	}
	return ""
}

// setup creates the first account: an admin director, signed in at once.
// The form carries the server's setup code, so the first visitor of an open
// port is not the one who gets it.
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if !s.noUsers() {
		http.NotFound(w, r)
		return
	}
	r.ParseForm()
	p := &page{Bare: true, Form: r.PostForm}
	// the setup code first, from the form's body only (an address ends up in
	// proxy and access logs). A server without a code makes no account: an
	// empty code never matches.
	code := r.PostForm.Get("code")
	if s.SetupCode == "" || subtle.ConstantTimeCompare([]byte(code), []byte(s.SetupCode)) != 1 {
		p.Error = "Setup code is wrong"
		s.renderStatus(w, http.StatusForbidden, "setup.html", p)
		return
	}
	name := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	switch {
	case !store.ValidID(name):
		p.Error = "Username: letters, digits, dot, dash, underscore"
	case emailProblem(email) != "":
		p.Error = emailProblem(email)
	default:
		p.Error = passwordProblem(r.FormValue("password"), r.FormValue("repeat"))
	}
	if p.Error != "" {
		s.renderStatus(w, http.StatusBadRequest, "setup.html", p)
		return
	}
	hash, err := auth.HashPassword(r.FormValue("password"))
	if err != nil {
		s.fail(w, err)
		return
	}
	d := s.Store.DB()
	err = d.AddFirstUser(config.User{Username: name, Email: email, Role: "director", PasswordHash: hash, IsAdmin: true})
	if errors.Is(err, db.ErrNotFirst) {
		http.NotFound(w, r)
		return
	}
	if errors.Is(err, db.ErrUserExists) { // the name of a deleted account
		p.Error = err.Error()
		s.renderStatus(w, http.StatusBadRequest, "setup.html", p)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.hasUsers.Store(true)
	// the simple workflow names the admin flag only, as Admin › Users does
	detail := "first run: director, admin"
	if s.flow().Simple {
		detail = "first run: admin"
	}
	d.Audit(name, "user.add", name, detail)
	tok, ok := s.Auth.Login(name, r.FormValue("password"))
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.Auth.SetCookie(w, tok)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// day shows a stored RFC 3339 time as a local date ("" when unset).
func day(at string) string {
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return at
	}
	return t.Local().Format("2006-01-02")
}

// when shows a stored RFC 3339 time as local date and minute.
func when(at string) string {
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return at
	}
	return t.Local().Format("2006-01-02 15:04")
}

// ending shows only the last four characters of a key: "…3f2a".
func ending(key string) string {
	r := []rune(key)
	if len(r) > 4 {
		r = r[len(r)-4:]
	}
	return "…" + string(r)
}
