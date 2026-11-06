package web

import (
	"net/http"
	"net/url"
	"strconv"
	"time"

	"yars/internal/auth"
	"yars/internal/db"
)

// activityAdmin is Admin › Activity: the audit log (filtered, a page at a
// time) and the signed-in sessions, each revocable; Tokens (its own tab)
// lists every API token.
type activityAdmin struct {
	Rows              []db.AuditEntry
	Actors, Actions   []option
	Actor, Action     string
	Total             int
	Range, Prev, Next string // "1–50 of 128" and the page links ("" = none)
	Sessions          []sessionRow
	Tokens            []tokenRow
}

type sessionRow struct {
	ID                      int64
	User, Created, LastSeen string
	Self                    bool
}

// auditGroups are the Action filter's choices (an action or its group).
var auditGroups = []option{{Value: "login", Label: "Sign-in"}, {Value: "user", Label: "Users"}, {Value: "token", Label: "Tokens"},
	{Value: "eng", Label: "Engagements"}, {Value: "export", Label: "Export"}, {Value: "settings", Label: "Settings"},
	{Value: "connection", Label: "Connections"}, {Value: "session", Label: "Sessions"}, {Value: "backup", Label: "Backup"},
	{Value: "system", Label: "System"}}

const auditPage = 50

func (s *Server) routesAdminActivity(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/activity", s.adminOnly(s.activityPage))
	mux.HandleFunc("GET /admin/tokens", s.adminOnly(s.tokensPage))
	mux.HandleFunc("POST /admin/activity/sessions/{id}/revoke", s.adminOnly(s.sessionRevoke))
	mux.HandleFunc("POST /admin/activity/tokens/{id}/revoke", s.adminOnly(s.adminTokenRevoke))
}

func (s *Server) activityPage(w http.ResponseWriter, r *http.Request) {
	s.adminPage(w, r, "activity", http.StatusOK, func(p *page) error {
		q := r.URL.Query()
		v := activityAdmin{Actor: q.Get("actor"), Action: q.Get("action")}
		off, _ := strconv.Atoi(q.Get("offset"))
		off = max(off, 0)
		d := s.Store.DB()
		var err error
		if v.Rows, v.Total, err = d.AuditQuery(db.AuditFilter{Actor: v.Actor, Action: v.Action, Limit: auditPage, Offset: off}); err != nil {
			return err
		}
		for i := range v.Rows {
			v.Rows[i].TS = when(v.Rows[i].TS)
		}
		actors, err := d.AuditActors()
		if err != nil {
			return err
		}
		for _, a := range actors {
			v.Actors = append(v.Actors, option{Value: a, Label: a, On: a == v.Actor})
		}
		for _, g := range auditGroups {
			g.On = g.Value == v.Action
			v.Actions = append(v.Actions, g)
		}
		page := func(o int) string {
			u := url.Values{}
			if v.Actor != "" {
				u.Set("actor", v.Actor)
			}
			if v.Action != "" {
				u.Set("action", v.Action)
			}
			if o > 0 {
				u.Set("offset", strconv.Itoa(o))
			}
			if e := u.Encode(); e != "" {
				return "/admin/activity?" + e
			}
			return "/admin/activity"
		}
		if v.Total > 0 {
			v.Range = strconv.Itoa(off+1) + "–" + strconv.Itoa(off+len(v.Rows)) + " of " + strconv.Itoa(v.Total)
		} else {
			v.Range = "0 of 0"
		}
		if off > 0 {
			v.Prev = page(max(off-auditPage, 0))
		}
		if off+auditPage < v.Total {
			v.Next = page(off + auditPage)
		}
		ss, err := d.Sessions()
		if err != nil {
			return err
		}
		for _, x := range ss {
			v.Sessions = append(v.Sessions, sessionRow{ID: x.ID, User: x.User, Created: when(x.Created), LastSeen: when(x.LastSeen)})
		}
		p.Admin.Activity = v
		return nil
	})
}

// tokensPage is Admin › Tokens: every API token, each revocable.
func (s *Server) tokensPage(w http.ResponseWriter, r *http.Request) {
	s.adminPage(w, r, "tokens", http.StatusOK, func(p *page) error {
		now := time.Now()
		for _, t := range s.Tokens.List() {
			p.Admin.Activity.Tokens = append(p.Admin.Activity.Tokens, tokenRowOf(t, now))
		}
		return nil
	})
}

func (s *Server) sessionRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.Store.DB().DeleteSessionID(id); err != nil {
		http.NotFound(w, r)
		return
	}
	s.Store.DB().Audit(auth.UserFrom(r.Context()).Username, "session.revoke", "", "#"+strconv.FormatInt(id, 10))
	http.Redirect(w, r, "/admin/activity#sessions", http.StatusSeeOther)
}

func (s *Server) adminTokenRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.Tokens.RevokeID(auth.UserFrom(r.Context()).Username, id, ""); err != nil {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/admin/tokens", http.StatusSeeOther)
}
