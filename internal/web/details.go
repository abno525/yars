package web

import (
	"errors"
	"net/http"
	"sort"
	"strings"

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
	ReadOnly                  bool // archived engagement: no Comment either
	ViewURL, EditURL, SaveURL string
}

func (s *Server) routesDetails(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/f/{fid}/details", s.detailsGet)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/details/edit", s.detailsEdit)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/details", s.detailsSave)
}

// rowField is the form field of a details row: keyed by its name, so a
// value lands under the row the editor showed even if the rows changed.
const rowField = "row:"

// detailsFor builds the view; typed overrides configured row values (by name).
func (s *Server) detailsFor(ref store.FindingRef, typed map[string]string) detailsView {
	d := ref.F.Meta.Details
	base := findingURL(ref.EngID, ref.Dir) + "/details"
	v := detailsView{Base: store.DetailsHash(ref.F.Meta), ViewURL: base, EditURL: base + "/edit", SaveURL: base,
		ReadOnly: s.Store.Archived(ref.EngID)}
	known := map[string]bool{}
	for _, name := range s.conf().DetailsRows {
		val := d[name]
		if t, ok := typed[name]; ok {
			val = t
		}
		v.Rows = append(v.Rows, detailsRow{Field: rowField + name, Name: name, Value: val})
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
	// a value is saved under the row name it was posted with: a configured
	// row, or one the finding already has; any other name means the rows
	// changed while the editor was open
	known := map[string]bool{}
	for _, name := range s.conf().DetailsRows {
		known[name] = true
	}
	for name := range ref.F.Meta.Details {
		known[name] = true
	}
	values := map[string]string{}
	gone := false
	for k, vs := range r.PostForm {
		if name, ok := strings.CutPrefix(k, rowField); ok && len(vs) > 0 {
			values[name] = vs[0]
			gone = gone || !known[name]
		}
	}
	err := store.ErrConflict
	if !gone {
		err = s.Store.UpdateDetails(ref.EngID, ref.Dir, values, r.PostForm.Get("base"), auth.UserFrom(r.Context()))
	}
	if errors.Is(err, store.ErrConflict) {
		v := s.detailsFor(ref, values)
		v.Error = "Details changed by someone else"
		if gone {
			v.Error = "Details rows changed"
		}
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
