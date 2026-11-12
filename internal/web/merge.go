package web

import (
	"errors"
	"net/http"
	"strings"

	"yars/internal/auth"
	"yars/internal/finding"
	"yars/internal/index"
	"yars/internal/store"
	"yars/internal/workflow"
)

// dupView lists possible duplicates of a finding or of a title being typed.
type dupView struct {
	Rows []dupRow
}

type dupRow struct {
	ID, Title, Shown, Severity string // Shown: workflow.Shown
	Pct                        int
	URL, MergeURL              string
}

// mergeView is the Merge confirm page.
type mergeView struct {
	ID, Title, URL, Back string
	Targets              []mergeTarget
	Parts                []mergePart
	Error                string
}

type mergeTarget struct {
	Dir, ID, Title, Shown, Severity string // Shown: workflow.Shown
	On                              bool
}

type mergePart struct {
	Name string
	N    int
}

func (s *Server) routesMerge(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/findings/new/dups", s.dupsWhileTyping)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/merge", s.mergePage)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/merge", s.mergePost)
}

// dupsOf turns index matches into rows; mergeFrom, when set, is the
// finding a director may merge into each of them.
func dupsOf(eng string, ms []index.Match, mergeFrom string) dupView {
	var v dupView
	for _, m := range ms {
		d := dupRow{ID: m.ID, Title: m.Title, Shown: m.Shown, Severity: m.Severity, Pct: m.Pct, URL: findingURL(eng, m.Dir)}
		if mergeFrom != "" {
			d.MergeURL = mergeFrom + "/merge?into=" + m.Dir
		}
		v.Rows = append(v.Rows, d)
	}
	return v
}

// dupsFor lists the possible duplicates of a finding in its engagement.
func (s *Server) dupsFor(r *http.Request, ref store.FindingRef) (dupView, error) {
	ms, err := s.Index.Similar(ref.EngID, ref.F.Meta.Title, ref.F.Meta.Assets, ref.F.Meta.ID)
	if err != nil {
		return dupView{}, err
	}
	from := ""
	if s.canMerge(r, ref) {
		from = findingURL(ref.EngID, ref.Dir)
	}
	return dupsOf(ref.EngID, ms, from), nil
}

// dupsWhileTyping is the New finding page's duplicate list for a title.
func (s *Server) dupsWhileTyping(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	if _, err := s.Store.Engagement(eng); err != nil {
		s.fail(w, err)
		return
	}
	ms, err := s.Index.Similar(eng, r.URL.Query().Get("title"), nil, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "new_finding.html", "dups_panel", dupsOf(eng, ms, ""))
}

// canMerge: a director, on a finding that is not withdrawn, in an
// engagement that is not archived.
func (s *Server) canMerge(r *http.Request, ref store.FindingRef) bool {
	return canManage(auth.UserFrom(r.Context())) && workflow.Active(ref.F.Meta.Status) && !s.Store.Archived(ref.EngID)
}

func nonEmptySections(f *finding.Finding) int {
	n := 0
	for _, sec := range f.Sections {
		if strings.TrimSpace(sec.Body) != "" {
			n++
		}
	}
	return n
}

func (s *Server) renderMerge(w http.ResponseWriter, r *http.Request, status int, into, errMsg string) {
	p, err := s.base(r, r.PathValue("eng"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if p.Finding, err = s.Store.Finding(p.Eng.ID, r.PathValue("fid")); err != nil {
		s.fail(w, err)
		return
	}
	ref := p.Finding
	if !s.canMerge(r, ref) {
		http.Error(w, "only a director can merge a finding that is not withdrawn", http.StatusForbidden)
		return
	}
	fu := findingURL(ref.EngID, ref.Dir)
	v := mergeView{ID: ref.F.Meta.ID, Title: ref.F.Meta.Title, URL: fu + "/merge", Back: fu, Error: errMsg}
	rows, err := s.Index.Rows(index.Query{EngID: ref.EngID})
	if err != nil {
		s.fail(w, err)
		return
	}
	for _, row := range rows {
		if row.Dir == ref.Dir {
			continue
		}
		v.Targets = append(v.Targets, mergeTarget{Dir: row.Dir, ID: row.ID, Title: row.Title, Shown: row.Shown, Severity: row.Severity, On: row.Dir == into})
	}
	atts, err := s.Store.AttachmentsOf(ref)
	if err != nil {
		s.fail(w, err)
		return
	}
	v.Parts = []mergePart{{"Sections", nonEmptySections(ref.F)}, {"Affected assets", len(ref.F.Meta.Assets)}, {"Attachments", len(atts)}}
	p.Merge = v
	s.renderStatus(w, status, "merge.html", p)
}

func (s *Server) mergePage(w http.ResponseWriter, r *http.Request) {
	s.renderMerge(w, r, http.StatusOK, r.URL.Query().Get("into"), "")
}

func (s *Server) mergePost(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	if !s.canMerge(r, ref) {
		http.Error(w, "only a director can merge a finding that is not withdrawn", http.StatusForbidden)
		return
	}
	into := r.FormValue("into")
	if into == "" {
		s.renderMerge(w, r, http.StatusBadRequest, "", "Pick the finding to merge into")
		return
	}
	dst, err := s.Store.Finding(ref.EngID, into)
	if errors.Is(err, store.ErrNotFound) {
		s.renderMerge(w, r, http.StatusBadRequest, "", "No finding "+into)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	err = s.Store.Merge(ref.EngID, ref.Dir, dst.Dir, auth.UserFrom(r.Context()))
	var d *workflow.Denied
	switch {
	case errors.As(err, &d):
		s.renderMerge(w, r, http.StatusBadRequest, into, d.Reason)
		return
	case errors.Is(err, store.ErrInvalidValue), errors.Is(err, store.ErrInvalidBody), errors.Is(err, store.ErrConflict):
		s.renderMerge(w, r, http.StatusBadRequest, into, err.Error())
		return
	case err != nil:
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, findingURL(dst.EngID, dst.Dir), http.StatusSeeOther)
}
