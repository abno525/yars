package web

import (
	"errors"
	"net/http"
	"sort"
	"strconv"

	"yars/internal/auth"
	"yars/internal/store"
)

type detailsRow struct {
	Field, Name, Value string
}

type detailsView struct {
	Rows, Other               []detailsRow
	Base, Error               string
	Locked                    bool
	ViewURL, EditURL, SaveURL string
}

func (s *Server) routesDetails(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/f/{fid}/details", s.detailsGet)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/details/edit", s.detailsEdit)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/details", s.detailsSave)
}

// detailsFor builds the view; typed overrides configured row values (by index).
func (s *Server) detailsFor(ref store.FindingRef, typed map[int]string) detailsView {
	d := ref.F.Meta.Details
	base := findingURL(ref.EngID, ref.Dir) + "/details"
	v := detailsView{Base: store.DetailsHash(ref.F.Meta), ViewURL: base, EditURL: base + "/edit", SaveURL: base}
	known := map[string]bool{}
	for i, name := range s.Cfg.DetailsRows {
		val := d[name]
		if t, ok := typed[i]; ok {
			val = t
		}
		v.Rows = append(v.Rows, detailsRow{Field: "row_" + strconv.Itoa(i), Name: name, Value: val})
		known[name] = true
	}
	for k, val := range d {
		if !known[k] {
			v.Other = append(v.Other, detailsRow{Name: k, Value: val})
		}
	}
	sort.Slice(v.Other, func(i, j int) bool { return v.Other[i].Name < v.Other[j].Name })
	return v
}

func (s *Server) detailsGet(w http.ResponseWriter, r *http.Request) {
	if ref, ok := s.cvssRef(w, r); ok {
		v := s.detailsFor(ref, nil)
		v.Locked = s.locked(r, ref)
		s.exec(w, "finding.html", "details_panel", v)
	}
}

func (s *Server) detailsEdit(w http.ResponseWriter, r *http.Request) {
	if ref, ok := s.editRef(w, r); ok {
		s.exec(w, "finding.html", "details_editor", s.detailsFor(ref, nil))
	}
}

func (s *Server) detailsSave(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.editRef(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	typed := map[int]string{}
	values := map[string]string{}
	for i, name := range s.Cfg.DetailsRows {
		f := "row_" + strconv.Itoa(i)
		if r.PostForm.Has(f) {
			typed[i] = r.PostForm.Get(f)
			values[name] = typed[i]
		}
	}
	err := s.Store.UpdateDetails(ref.EngID, ref.Dir, values, r.PostForm.Get("base"), auth.UserFrom(r.Context()))
	if errors.Is(err, store.ErrConflict) {
		v := s.detailsFor(ref, typed)
		v.Error = "The details were changed by someone else while you were editing. Your text is kept below; saving again will replace theirs."
		s.execStatus(w, http.StatusConflict, "finding.html", "details_editor", v)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if ref, err = s.Store.Finding(ref.EngID, ref.Dir); err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "finding.html", "details_panel", s.detailsFor(ref, nil))
}
