package web

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/store"
)

type detailsRow struct {
	Field, Name, Value string
	BaseField, Base    string // the row's own base (store.RowHash of its stored value)
}

type detailsView struct {
	Rows, Other               []detailsRow
	Base, Error               string
	Locked                    bool
	ReadOnly                  bool // archived engagement: no Comment either
	ViewURL, EditURL, SaveURL string
	LiveURL                   string // the read panel's live refresh
}

func (s *Server) routesDetails(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/f/{fid}/details", s.detailsGet)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/details/edit", s.detailsEdit)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/details", s.detailsSave)
}

// rowField is the form field of a details row: keyed by its name, so a
// value lands under the row the editor showed even if the rows changed.
const rowField = "row:"

// baseField is the form field of a row's base: each row is checked on its
// own, and only rows the user changed are written.
const baseField = "base:"

// detailsFor builds the view; typed overrides configured row values (by name).
func (s *Server) detailsFor(ref store.FindingRef, typed map[string]string) detailsView {
	d := ref.F.Meta.Details
	base := findingURL(ref.EngID, ref.Dir) + "/details"
	v := detailsView{Base: store.DetailsHash(ref.F.Meta), ViewURL: base, EditURL: base + "/edit", SaveURL: base,
		ReadOnly: s.Store.Archived(ref.EngID), LiveURL: s.liveURL(base, ref)}
	known := map[string]bool{}
	for _, name := range s.conf().DetailsRows {
		val := d[name]
		if t, ok := typed[name]; ok {
			val = t
		}
		v.Rows = append(v.Rows, detailsRow{Field: rowField + name, Name: name, Value: val,
			BaseField: baseField + name, Base: store.RowHash(d[name])})
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
	if ref, ok := s.liveRef(w, r); ok {
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
	values, bases := map[string]string{}, map[string]string{}
	perRow, gone := false, false
	for k, vs := range r.PostForm {
		if name, ok := strings.CutPrefix(k, baseField); ok && len(vs) > 0 {
			bases[name], perRow = vs[0], true
		}
	}
	for k, vs := range r.PostForm {
		if name, ok := strings.CutPrefix(k, rowField); ok && len(vs) > 0 {
			gone = gone || !known[name]
			// per row: a row the user left as it was is not written, so a
			// change made meanwhile (MCP, a push) stays
			if b, ok := bases[name]; perRow && ok && store.RowHash(store.CleanRow(vs[0])) == b {
				continue
			}
			values[name] = vs[0]
		}
	}
	var err error
	switch {
	case gone:
		err = store.ErrConflict
	case perRow && len(values) == 0:
	case perRow:
		_, err = s.Store.UpdateDetailsRows(ref.EngID, ref.Dir, values, bases, auth.UserFrom(r.Context()))
	default:
		err = s.Store.UpdateDetails(ref.EngID, ref.Dir, values, r.PostForm.Get("base"), auth.UserFrom(r.Context()))
	}
	if errors.Is(err, store.ErrConflict) {
		// the rows the user changed, typed; the others as they are now
		v := s.detailsFor(ref, values)
		v.Error = conflictText
		if gone {
			// a row the editor showed is no longer configured
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
