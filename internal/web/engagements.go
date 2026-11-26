package web

import (
	"net/http"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/workflow"
)

// engFilters are the engagements list's segments: key, label.
var engFilters = []struct{ Key, Label string }{{"", "All"}, {"active", "Active"}, {"archived", "Archived"}}

// engList fills the engagements list: the All / Active / Archived segments
// with counts and the rows the chosen one shows.
func (s *Server) engList(p *page, show string) error {
	if p.engsErr != nil { // no list rather than an empty one
		return p.engsErr
	}
	if show != "active" && show != "archived" {
		show = ""
	}
	n := map[string]int{"": len(p.Engagements)}
	for _, e := range p.Engagements {
		if e.Archived {
			n["archived"]++
		} else {
			n["active"]++
		}
	}
	for _, f := range engFilters {
		u := "/engagements"
		if f.Key != "" {
			u += "?show=" + f.Key
		}
		p.StatusFilters = append(p.StatusFilters, link{Key: f.Key, Label: f.Label, URL: u, Active: f.Key == show, Count: n[f.Key],
			Keys: filterKey(len(p.StatusFilters))})
	}
	p.EngShow = show
	engs := p.Engagements[:0:0]
	for _, e := range p.Engagements {
		if (show == "active" && e.Archived) || (show == "archived" && !e.Archived) {
			continue
		}
		engs = append(engs, e)
	}
	var err error
	p.EngRows, err = s.engRows(engs)
	return err
}

// dateRange shows an engagement's dates compactly: "04–07 Nov",
// "28 Nov–03 Dec", "04 Nov"; "—" without a start.
func dateRange(start, end string) string {
	if start == "" {
		return "—"
	}
	a, err := time.Parse("2006-01-02", start)
	if err != nil {
		return start
	}
	b, err := time.Parse("2006-01-02", end)
	switch {
	case err != nil:
		return a.Format("02 Jan")
	case a.Year() == b.Year() && a.Month() == b.Month():
		return a.Format("02") + "–" + b.Format("02 Jan")
	}
	return a.Format("02 Jan") + "–" + b.Format("02 Jan")
}

// engArchive archives (on) or reopens an engagement, directors only. From
// the engagements list (a show field) it goes back to the list and its
// filter, otherwise to the engagement.
func (s *Server) engArchive(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := auth.UserFrom(r.Context())
		eng := r.PathValue("eng")
		if !canManage(u) {
			s.fail(w, &workflow.Denied{Reason: "only a director can archive or reopen an engagement"})
			return
		}
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
		to := "/e/" + eng
		r.ParseForm()
		if show, ok := r.PostForm["show"]; ok {
			to = "/engagements"
			if v := show[0]; v == "active" || v == "archived" {
				to += "?show=" + v
			}
		}
		http.Redirect(w, r, to, http.StatusSeeOther)
	}
}
