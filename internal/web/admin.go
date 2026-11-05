package web

import (
	"net/http"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/workflow"
)

// canAdmin reports whether u may open the admin pages: the admin flag,
// separate from the role (which keeps the workflow powers).
func canAdmin(u config.User) bool { return u.IsAdmin }

// adminTab is one entry of the admin tab list; an empty URL keeps the
// entry's slot without showing it (not built yet).
type adminTab struct {
	Label, URL string
	On         bool
}

var adminTabs = []struct{ Key, Label, URL string }{
	{"users", "Users", "/admin/users"}, {"engagements", "Engagements", "/admin/engagements"}, {"rules", "Rules", "/admin/rules"},
	{"ai", "AI", "/admin/ai"}, {"system", "System", "/admin/system"}, {"health", "Health", "/admin/health"},
	{"activity", "Activity", "/admin/activity"}, {"structure", "Structure", ""}, {"exports", "Exports", ""},
}

type adminView struct {
	Tab      string
	Tabs     []adminTab
	Rules    rulesAdmin
	Users    usersAdmin
	Engs     engsAdmin
	AI       aiAdmin
	System   systemAdmin
	Health   healthAdmin
	Activity activityAdmin
}

func (s *Server) routesAdmin(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	}))
	s.routesAdminRules(mux)
	s.routesAdminUsers(mux)
	s.routesAdminEngagements(mux)
	s.routesAdminAI(mux)
	s.routesAdminSystem(mux)
	s.routesAdminActivity(mux)
}

// adminOnly answers 403 to users who may not administer.
func (s *Server) adminOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !canAdmin(auth.UserFrom(r.Context())) {
			s.fail(w, &workflow.Denied{Reason: "admin only"})
			return
		}
		h(w, r)
	}
}

// adminBase is the common data of an admin page on tab.
func (s *Server) adminBase(r *http.Request, tab string) (*page, error) {
	p, err := s.base(r, "")
	if err != nil {
		return nil, err
	}
	p.Nav = "admin"
	p.Admin.Tab = tab
	for _, t := range adminTabs {
		p.Admin.Tabs = append(p.Admin.Tabs, adminTab{Label: t.Label, URL: t.URL, On: t.Key == tab})
	}
	return p, nil
}

// adminPage renders tab's page after fill added its data; status is the
// HTTP status (400 to show a form's error).
func (s *Server) adminPage(w http.ResponseWriter, r *http.Request, tab string, status int, fill func(*page) error) {
	p, err := s.adminBase(r, tab)
	if err != nil {
		s.fail(w, err)
		return
	}
	if err := fill(p); err != nil {
		s.fail(w, err)
		return
	}
	s.renderStatus(w, status, "admin.html", p)
}
