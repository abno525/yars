package web

import (
	"net/http"

	"yars/internal/auth"
)

// D26: an account with a temporary password (an admin's Add user or Reset
// password) sets a new one before anything else.

func (s *Server) routesPassword(mux *http.ServeMux) {
	mux.HandleFunc("GET /password", s.passwordPage)
	mux.HandleFunc("POST /password", s.passwordSet)
}

// mustChangeGate lets an account with a temporary password reach only the
// set-password page and Log out: a page leads there, an htmx request is
// sent there (HX-Redirect), anything else is refused.
func (s *Server) mustChangeGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !auth.UserFrom(r.Context()).MustChange || r.URL.Path == "/password" || (r.Method == http.MethodPost && r.URL.Path == "/logout") {
			next.ServeHTTP(w, r)
			return
		}
		switch {
		case r.Header.Get("HX-Request") == "true":
			w.Header().Set("HX-Redirect", "/password")
			http.Error(w, "Set a new password first", http.StatusForbidden)
		case r.Method == http.MethodGet && r.URL.Path != "/events":
			http.Redirect(w, r, "/password", http.StatusSeeOther)
		default:
			http.Error(w, "Set a new password first", http.StatusForbidden)
		}
	})
}

func (s *Server) passwordPage(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	if !u.MustChange {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "password.html", &page{Bare: true, User: u})
}

func (s *Server) passwordSet(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	if !u.MustChange {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	pw := r.FormValue("new")
	msg := passwordProblem(pw, r.FormValue("repeat"))
	if msg == "" && s.Auth.Verify(u.Username, pw) {
		msg = "Choose a password other than the temporary one"
	}
	if msg != "" {
		s.renderStatus(w, http.StatusBadRequest, "password.html", &page{Bare: true, User: u, Error: msg})
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.fail(w, err)
		return
	}
	// every session of the account ends (the temporary one too); this
	// browser signs in again with the new password
	if err := s.Store.DB().ChangePassword(u.Username, hash); err != nil {
		s.fail(w, err)
		return
	}
	s.Store.DB().Audit(u.Username, "user.password", u.Username, "first login")
	if tok, ok := s.Auth.Login(u.Username, pw); ok {
		auth.SetCookie(w, tok)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
