package web

import (
	"net/http"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/workflow"
)

// canAdmin reports whether u may open the admin pages. The one place that
// decides it (directors for now; the admin flag later).
func canAdmin(u config.User) bool { return workflow.AtLeast(u, "director") }

// adminTab is one entry of the admin tab list; an empty URL keeps the
// entry's slot without showing it (not built yet).
type adminTab struct {
	Label, URL string
	On         bool
}

var adminTabs = []struct{ Key, Label, URL string }{
	{"users", "Users", ""}, {"engagements", "Engagements", ""}, {"rules", "Rules", "/admin/rules"}, {"ai", "AI", ""},
	{"system", "System", ""}, {"activity", "Activity", ""}, {"structure", "Structure", ""}, {"exports", "Exports", ""},
}

type adminView struct {
	Tab   string
	Tabs  []adminTab
	Rules rulesAdmin
}

func (s *Server) routesAdmin(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/rules", http.StatusSeeOther)
	}))
	s.routesAdminRules(mux)
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
