package web

import (
	"net/http"
	"net/url"
	"slices"
	"strings"

	"yars/internal/auth"
	"yars/internal/store"
)

// engsAdmin is Admin › Engagements: every engagement (archived ones
// included) with its team size and state, the New engagement form and the
// team editor of one engagement.
type engsAdmin struct {
	Rows    []engAdminRow
	Filters []link
	Users   []option // the New engagement form's team choices
	Team    *teamEdit
	Error   string
	Form    url.Values
	// CanReopen: reopening is for directors (the admin flag alone archives)
	CanReopen bool
}

type engAdminRow struct {
	store.Engagement
	Team, Findings int
	ArchivedAt     string
	ArchivedBy     string
	Editing        bool
}

type teamEdit struct {
	Eng     store.Engagement
	Members []option // Value = user, Label = role
	Others  []option // users not on the team
}

func (s *Server) routesAdminEngagements(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/engagements", s.adminOnly(func(w http.ResponseWriter, r *http.Request) {
		s.engsPage(w, r, http.StatusOK, engsAdmin{})
	}))
	mux.HandleFunc("POST /admin/engagements", s.adminOnly(s.engCreate))
	mux.HandleFunc("POST /admin/engagements/{eng}/archive", s.adminOnly(s.engArchive(true)))
	mux.HandleFunc("POST /admin/engagements/{eng}/reopen", s.adminOnly(s.engArchive(false)))
	mux.HandleFunc("POST /admin/engagements/{eng}/team", s.adminOnly(s.teamAdd))
	mux.HandleFunc("POST /admin/engagements/{eng}/team/remove", s.adminOnly(s.teamRemove))
}

func (s *Server) engsPage(w http.ResponseWriter, r *http.Request, status int, v engsAdmin) {
	s.adminPage(w, r, "engagements", status, func(p *page) error {
		q := r.URL.Query()
		show := q.Get("show")
		engs, err := s.Index.Engagements()
		if err != nil {
			return err
		}
		archived, err := s.Store.DB().ArchivedEngagements()
		if err != nil {
			return err
		}
		n := map[string]int{"": len(engs)}
		for _, e := range engs {
			if e.Archived {
				n["archived"]++
			} else {
				n["active"]++
			}
		}
		for _, f := range []struct{ Key, Label string }{{"", "All"}, {"active", "Active"}, {"archived", "Archived"}} {
			u := "/admin/engagements"
			if f.Key != "" {
				u += "?show=" + f.Key
			}
			v.Filters = append(v.Filters, link{Label: f.Label, URL: u, Active: f.Key == show, Count: n[f.Key]})
		}
		team := q.Get("team")
		for _, e := range engs {
			if (show == "active" && e.Archived) || (show == "archived" && !e.Archived) {
				continue
			}
			members, err := s.Store.Members(e.ID)
			if err != nil {
				return err
			}
			sum, err := s.Index.Summary(e.ID)
			if err != nil {
				return err
			}
			row := engAdminRow{Engagement: e, Team: len(members), Findings: sum.Total, Editing: e.ID == team}
			if m, ok := archived[e.ID]; ok {
				row.ArchivedAt, row.ArchivedBy = day(m.ArchivedAt), m.ArchivedBy
			}
			v.Rows = append(v.Rows, row)
		}
		users, err := s.Store.DB().Users()
		if err != nil {
			return err
		}
		picked := v.Form["member"]
		for _, u := range users {
			if !u.Disabled {
				v.Users = append(v.Users, option{Value: u.Username, Label: u.Role, On: slices.Contains(picked, u.Username)})
			}
		}
		if e, ok := s.Index.Engagement(team); ok {
			members, err := s.Store.Members(e.ID)
			if err != nil {
				return err
			}
			t := &teamEdit{Eng: e}
			for _, u := range users {
				o := option{Value: u.Username, Label: u.Role}
				if slices.Contains(members, u.Username) {
					t.Members = append(t.Members, o)
				} else if !u.Disabled {
					t.Others = append(t.Others, o)
				}
			}
			v.Team = t
		}
		v.CanReopen = canManage(p.User)
		p.Admin.Engs = v
		return nil
	})
}

// engCreate makes a new engagement and puts the ticked people on its team.
func (s *Server) engCreate(w http.ResponseWriter, r *http.Request) {
	actor := auth.UserFrom(r.Context())
	r.ParseForm()
	v := engsAdmin{Form: r.PostForm}
	e := store.Engagement{ID: strings.TrimSpace(r.FormValue("id")), Name: strings.TrimSpace(r.FormValue("name")),
		Client: strings.TrimSpace(r.FormValue("client")), Type: "pentest", Start: r.FormValue("start"), End: r.FormValue("end")}
	switch {
	case !store.ValidID(e.ID):
		v.Error = "ID: letters, digits, dot, dash, underscore"
	case e.Name == "":
		v.Error = "Name is required"
	}
	if v.Error == "" {
		if err := s.Store.CreateEngagement(e, author(actor)); err != nil {
			v.Error = err.Error()
		}
	}
	if v.Error != "" {
		s.engsPage(w, r, http.StatusBadRequest, v)
		return
	}
	var team []string
	for _, m := range r.PostForm["member"] {
		if u, ok := s.Auth.Lookup(m); ok && !slices.Contains(team, u.Username) {
			team = append(team, u.Username)
		}
	}
	if len(team) > 0 {
		if err := s.Store.AddMembers(e.ID, team, actor); err != nil {
			s.fail(w, err)
			return
		}
	}
	s.Store.DB().Audit(actor.Username, "eng.create", e.ID, strings.Join(team, ","))
	http.Redirect(w, r, "/admin/engagements?team="+url.QueryEscape(e.ID), http.StatusSeeOther)
}

// engArchive archives (directors and admins) or reopens (directors) an
// engagement.
func (s *Server) engArchive(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := auth.UserFrom(r.Context())
		eng := r.PathValue("eng")
		var err error
		if on {
			err = s.Store.Archive(eng, u)
		} else {
			err = s.Store.Unarchive(eng, u)
		}
		if err != nil {
			s.fail(w, err)
			return
		}
		http.Redirect(w, r, "/admin/engagements", http.StatusSeeOther)
	}
}

// teamAdd puts one person (user) or everyone (everyone=1) on the team.
func (s *Server) teamAdd(w http.ResponseWriter, r *http.Request) {
	actor := auth.UserFrom(r.Context())
	eng := r.PathValue("eng")
	var add []string
	if r.FormValue("everyone") == "1" {
		users, err := s.Store.DB().Users()
		if err != nil {
			s.fail(w, err)
			return
		}
		for _, u := range users {
			if !u.Disabled {
				add = append(add, u.Username)
			}
		}
	} else if u, ok := s.Auth.Lookup(r.FormValue("user")); ok {
		add = []string{u.Username}
	} else {
		http.Error(w, "unknown user", http.StatusBadRequest)
		return
	}
	if err := s.Store.AddMembers(eng, add, actor); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/admin/engagements?team="+url.QueryEscape(eng), http.StatusSeeOther)
}

func (s *Server) teamRemove(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	if _, err := s.Store.Engagement(eng); err != nil {
		s.fail(w, err)
		return
	}
	if err := s.Store.RemoveMember(eng, r.FormValue("user"), auth.UserFrom(r.Context())); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/admin/engagements?team="+url.QueryEscape(eng), http.StatusSeeOther)
}
