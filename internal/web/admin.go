package web

import (
	"net/http"
	"strconv"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/workflow"
)

// canAdmin reports whether u may open the admin pages: the admin flag,
// separate from the role (which keeps the workflow powers).
func canAdmin(u config.User) bool { return u.IsAdmin }

// adminTab is one entry of the admin tab list; an empty URL keeps the
// entry's slot without showing it (not built yet).
type adminTab struct {
	Label, URL string
	On         bool
	Dot        string // a red dot with this title: something is wrong there
}

// adminTabs is the tab bar of every admin page. Engagements are managed on
// the engagements list; System is the health page. Webhooks has no tab
// (its page keeps its address, linked from the admin footer's docs).
var adminTabs = []struct{ Key, Label, URL string }{
	{"users", "Users", "/admin/users"}, {"rules", "Rules", "/admin/rules"}, {"structure", "Structure", "/admin/structure"},
	{"ai", "AI", "/admin/ai"}, {"system", "System", "/admin/system"}, {"activity", "Activity", "/admin/activity"},
	{"tokens", "Tokens", "/admin/tokens"},
}

// tabExtras are the counts on the Users, Rules and Tokens tabs and the
// dots on Rules (a rule doesn't load) and System (the last health check
// found an error). They read what is at hand; no check runs for them.
func (s *Server) tabExtras() (counts map[string]int, dots map[string]string) {
	counts, dots = map[string]int{}, map[string]string{}
	if n, err := s.Store.DB().UserCount(); err == nil {
		counts["users"] = n
	}
	if s.Rules != nil {
		set := s.Rules.Rules()
		counts["rules"] = len(set.Rules)
		if n := len(set.Problems); n > 0 {
			dots["rules"] = strconv.Itoa(n) + " invalid"
		}
	}
	counts["tokens"] = len(s.Tokens.List())
	if h := s.lastHealth.Load(); h != nil && h.Errors > 0 {
		dots["system"] = plural(h.Errors, "error")
	}
	return counts, dots
}

type adminView struct {
	Tab       string
	Tabs      []adminTab
	Rules     rulesAdmin
	Users     usersAdmin
	AI        aiAdmin
	System    systemAdmin
	Activity  activityAdmin
	Structure structView
	Hooks     hooksAdmin
}

func (s *Server) routesAdmin(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin", s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
	}))
	// Admin › Engagements was folded into the engagements list
	mux.HandleFunc("GET /admin/engagements", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/engagements", http.StatusSeeOther)
	})
	s.routesAdminRules(mux)
	s.routesAdminUsers(mux)
	s.routesAdminAI(mux)
	s.routesAdminSystem(mux)
	s.routesAdminActivity(mux)
	s.routesAdminStructure(mux)
	s.routesAdminWebhooks(mux)
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
	counts, dots := s.tabExtras()
	for _, t := range adminTabs {
		label := t.Label
		if n, ok := counts[t.Key]; ok {
			label += " · " + strconv.Itoa(n)
		}
		p.Admin.Tabs = append(p.Admin.Tabs, adminTab{Label: label, URL: t.URL, On: t.Key == tab, Dot: dots[t.Key]})
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
