package web

import (
	"crypto/rand"
	"net/http"
	"net/url"
	"strings"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/store"
)

// usersAdmin is Admin › Users: every account with its role, flags and
// tokens, the Add user form, and a temporary password shown once.
type usersAdmin struct {
	Rows  []userRow
	Roles []string
	Temp  *tempPassword
	Error string
	Form  url.Values
}

type userRow struct {
	config.User
	Tokens int
	Self   bool
	Locked string // locked out of password logins until (HH:MM); "" = not
}

type tempPassword struct{ User, Password string }

func (s *Server) routesAdminUsers(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/users", s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
		s.usersPage(w, r, http.StatusOK, usersAdmin{})
	}))
	mux.HandleFunc("POST /admin/users", s.adminOnly(s.userAdd))
	mux.HandleFunc("POST /admin/users/{name}/role", s.adminOnly(s.userRole))
	mux.HandleFunc("POST /admin/users/{name}/admin", s.adminOnly(s.userFlag("admin")))
	mux.HandleFunc("POST /admin/users/{name}/disabled", s.adminOnly(s.userFlag("disabled")))
	mux.HandleFunc("POST /admin/users/{name}/reset", s.adminOnly(s.userReset))
	mux.HandleFunc("POST /admin/users/{name}/unlock", s.adminOnly(s.userUnlock))
}

// userUnlock ends the account's login lockout (D27).
func (s *Server) userUnlock(w http.ResponseWriter, r *http.Request) {
	u, ok := s.target(w, r)
	if !ok {
		return
	}
	if err := s.Store.DB().ClearLockout(u.Username); err != nil {
		s.fail(w, err)
		return
	}
	s.Store.DB().Audit(auth.UserFrom(r.Context()).Username, "login.unlock", u.Username, "")
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request, status int, v usersAdmin) {
	s.adminPage(w, r, "users", status, func(p *page) error {
		users, err := s.Store.DB().Users()
		if err != nil {
			return err
		}
		count := map[string]int{}
		for _, t := range s.Tokens.List() {
			count[t.User]++
		}
		locks, err := s.Store.DB().Lockouts()
		if err != nil {
			return err
		}
		for _, u := range users {
			u.Created = day(u.Created)
			row := userRow{User: u, Tokens: count[u.Username], Self: u.Username == p.User.Username}
			if t, ok := locks[u.Username]; ok {
				row.Locked = t.Local().Format("15:04")
			}
			v.Rows = append(v.Rows, row)
		}
		v.Roles = config.Roles
		if v.Form == nil {
			v.Form = url.Values{"role": {"pentester"}}
		}
		p.Admin.Users = v
		return nil
	})
}

// newTempPassword makes a random temporary password: three groups of four
// letters and digits (no look-alikes).
func newTempPassword() string {
	const chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 12)
	rand.Read(b)
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(chars[int(c)%len(chars)])
	}
	return sb.String()
}

// userAdd adds an account with a temporary password (typed or generated),
// shown once. In the simple workflow every account is a director: a posted
// role is ignored.
func (s *Server) userAdd(w http.ResponseWriter, r *http.Request) {
	actor := auth.UserFrom(r.Context())
	r.ParseForm()
	v := usersAdmin{Form: r.PostForm}
	name := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	pw := r.FormValue("password")
	if pw == "" {
		pw = newTempPassword()
	}
	simple := s.flow().Simple
	role := r.FormValue("role")
	if simple {
		role = "director"
	}
	switch {
	case !store.ValidID(name):
		v.Error = "Username: letters, digits, dot, dash, underscore"
	case !config.ValidRole(role):
		v.Error = "Role: " + strings.Join(config.Roles, ", ")
	case emailProblem(email) != "":
		v.Error = emailProblem(email)
	case newPasswordProblem(pw) != "":
		v.Error = newPasswordProblem(pw)
	}
	if v.Error == "" {
		if _, ok, _ := s.Store.DB().User(name); ok {
			v.Error = "User " + name + " exists"
		}
	}
	if v.Error != "" {
		s.usersPage(w, r, http.StatusBadRequest, v)
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.fail(w, err)
		return
	}
	// the password is the admin's, given to the user: they set their own
	// on first login
	u := config.User{Username: name, Email: email, Role: role, PasswordHash: hash, IsAdmin: r.FormValue("admin") == "1", MustChange: true}
	if err := s.Store.DB().AddUser(u); err != nil {
		v.Error = err.Error()
		s.usersPage(w, r, http.StatusBadRequest, v)
		return
	}
	// "pentester, admin"; the simple workflow names the admin flag only
	var detail []string
	if !simple {
		detail = append(detail, u.Role)
	}
	if u.IsAdmin {
		detail = append(detail, "admin")
	}
	s.Store.DB().Audit(actor.Username, "user.add", name, strings.Join(detail, ", "))
	w.Header().Set("Cache-Control", "no-store")
	s.usersPage(w, r, http.StatusOK, usersAdmin{Temp: &tempPassword{User: name, Password: pw}})
}

// target loads the account named in the path (404 when unknown).
func (s *Server) target(w http.ResponseWriter, r *http.Request) (config.User, bool) {
	u, ok, err := s.Store.DB().User(r.PathValue("name"))
	if err != nil {
		s.fail(w, err)
		return u, false
	}
	if !ok {
		http.NotFound(w, r)
	}
	return u, ok
}

// userRole sets an account's role; the simple workflow has none to set.
func (s *Server) userRole(w http.ResponseWriter, r *http.Request) {
	if s.flow().Simple {
		s.usersPage(w, r, http.StatusBadRequest, usersAdmin{Error: "The simple workflow has no roles"})
		return
	}
	u, ok := s.target(w, r)
	if !ok {
		return
	}
	role := r.FormValue("role")
	if !config.ValidRole(role) {
		s.usersPage(w, r, http.StatusBadRequest, usersAdmin{Error: "Role: " + strings.Join(config.Roles, ", ")})
		return
	}
	if err := s.Store.DB().SetRole(u.Username, role); err != nil {
		s.fail(w, err)
		return
	}
	s.Store.DB().Audit(auth.UserFrom(r.Context()).Username, "user.role", u.Username, role)
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// userFlag turns the admin or disabled flag on (on=1) or off. Admins can't
// take their own admin flag or disable themselves.
func (s *Server) userFlag(flag string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := s.target(w, r)
		if !ok {
			return
		}
		actor := auth.UserFrom(r.Context())
		on := r.FormValue("on") == "1"
		d := s.Store.DB()
		var err error
		var action string
		switch flag {
		case "admin":
			if !on && u.Username == actor.Username {
				s.usersPage(w, r, http.StatusBadRequest, usersAdmin{Error: "Your own admin flag stays"})
				return
			}
			err, action = d.SetAdmin(u.Username, on), "user.admin"
		case "disabled":
			if on && u.Username == actor.Username {
				s.usersPage(w, r, http.StatusBadRequest, usersAdmin{Error: "You can't disable yourself"})
				return
			}
			err, action = d.SetDisabled(u.Username, on), "user.enable"
			if on {
				action = "user.disable"
			}
		}
		if err != nil {
			s.fail(w, err)
			return
		}
		// user.admin says which way; user.disable / user.enable say it themselves
		detail := ""
		if flag == "admin" {
			detail = "off"
			if on {
				detail = "on"
			}
		}
		d.Audit(actor.Username, action, u.Username, detail)
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	}
}

// userReset gives the account a new temporary password, shown once; its
// sessions end and the user sets a new password on the next login.
func (s *Server) userReset(w http.ResponseWriter, r *http.Request) {
	u, ok := s.target(w, r)
	if !ok {
		return
	}
	pw := newTempPassword()
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := s.Store.DB().ResetPassword(u.Username, hash); err != nil {
		s.fail(w, err)
		return
	}
	s.Store.DB().Audit(auth.UserFrom(r.Context()).Username, "user.password", u.Username, "reset")
	w.Header().Set("Cache-Control", "no-store")
	s.usersPage(w, r, http.StatusOK, usersAdmin{Temp: &tempPassword{User: u.Username, Password: pw}})
}
