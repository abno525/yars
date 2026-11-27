package web

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/cvss"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

type retestOption struct {
	Code, Label string
	Checked     bool
}

type retestView struct {
	Result, Source, SourceURL string
	SourceStatus, SourceSev   string
	SourceMissing             bool
	// Copied: the panel shows the text as it was copied into the retest, not
	// the original as it is (the viewer is not on the original's team): no
	// status tag, no Open link
	Copied  bool
	Options []retestOption
	URL, Error                string
	Locked                    bool
	// the original, shown beside the result
	Details       []detailsRow
	Vector, Score string
	Sections      []tplSection
}

func (s *Server) routesRetest(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/retest/new", s.retestForm)
	mux.HandleFunc("POST /e/{eng}/retest/new", s.retestCreate)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/retest", s.retestSave)
}

// retestFor builds the panel; nil when the finding isn't a retest.
func (s *Server) retestFor(r *http.Request, ref store.FindingRef) *retestView {
	rt := ref.F.Meta.Retest
	if rt == nil {
		return nil
	}
	v := &retestView{Result: rt.Result, Source: rt.Source, URL: findingURL(ref.EngID, ref.Dir) + "/retest", Locked: s.locked(r, ref)}
	// show fills the panel's body from f; its pictures are those of at
	show := func(f *finding.Finding, at store.FindingRef) {
		m := f.Meta
		v.SourceSev = cvss.Derive(m.CVSS, m.Severity)
		for _, name := range s.conf().DetailsRows {
			if x := strings.TrimSpace(m.Details[name]); x != "" {
				v.Details = append(v.Details, detailsRow{Name: name, Value: x})
			}
		}
		if vec, err := cvss.Parse(m.CVSS); err == nil {
			n, _ := cvss.Score(vec)
			v.Vector, v.Score = vec.String(), cvss.FormatScore(n)
		}
		for _, sec := range f.Sections {
			if strings.TrimSpace(sec.Body) != "" {
				v.Sections = append(v.Sections, tplSection{Name: sec.Name, HTML: s.linkAttachments(s.renderMD(sec.Body), at)})
			}
		}
	}
	if eng, dir, ok := strings.Cut(rt.Source, "/"); ok {
		v.SourceURL = findingURL(eng, dir)
		// the original as it is now, with its status and a link to it, only
		// for those on its engagement's team
		if src, err := s.Store.Finding(eng, dir); err == nil && s.Store.CanSee(auth.UserFrom(r.Context()), eng) {
			v.SourceStatus = workflow.Shown(src.F.Meta)
			show(src.F, src)
		} else if f := s.copiedOriginal(ref); f != nil {
			// anyone else (the retester from outside that team; also when the
			// original is gone) sees what was copied into the retest: the
			// copy's first version, out of the retest's own repository, which
			// they are on the team of. Nothing is read from the source, and
			// the pictures are the copy's.
			v.Copied = true
			show(f, ref)
		} else {
			v.SourceMissing = true
		}
	} else {
		v.SourceMissing = true // names no finding
	}
	for _, c := range []string{"fixed", "partially_fixed", "not_fixed"} { // the board's order
		v.Options = append(v.Options, retestOption{Code: c, Label: workflow.RetestLabel(c), Checked: c == rt.Result})
	}
	return v
}

// copiedOriginal is the retest finding ref as it was copied from its
// original: the first version of its file in the retest's repository (the
// retest's first commit wrote it). nil when that cannot be read. It starts
// git (cached per HEAD, as History), so it is asked only when the original
// itself cannot be shown.
func (s *Server) copiedOriginal(ref store.FindingRef) *finding.Finding {
	vs, err := s.versions(ref)
	if err != nil || len(vs) == 0 {
		return nil
	}
	raw := vs[len(vs)-1].Raw // newest first: the last is the first version
	if raw == nil {
		return nil
	}
	f, err := finding.Parse(raw)
	if err != nil {
		return nil
	}
	return f
}

func (s *Server) retestSave(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.editRef(w, r)
	if !ok {
		return
	}
	err := s.Store.SetRetestResultFrom(ref.EngID, ref.Dir, r.FormValue("was"), r.FormValue("result"), auth.UserFrom(r.Context()))
	conflict := errors.Is(err, store.ErrConflict)
	if err != nil && !errors.Is(err, store.ErrInvalidValue) && !conflict {
		s.fail(w, err)
		return
	}
	status := http.StatusOK
	if err == nil || conflict {
		if ref, err = s.Store.Finding(ref.EngID, ref.Dir); err != nil {
			s.fail(w, err)
			return
		}
	}
	v := s.retestFor(r, ref)
	if v == nil {
		http.Error(w, "not a retest finding", http.StatusBadRequest)
		return
	}
	if conflict {
		// the panel as it is now: the choice is made again on it
		status, v.Error = http.StatusConflict, "the result changed since you opened the page; choose again"
	} else if err != nil {
		status, v.Error = http.StatusBadRequest, err.Error()
	} else {
		// the result feeds the submit gate: reload so the workflow bar updates
		w.Header().Set("HX-Refresh", "true")
	}
	s.execStatus(w, status, "finding.html", "retest_panel", v)
}

func (s *Server) retestPage(r *http.Request) (*page, bool, error) {
	p, err := s.base(r, r.PathValue("eng"))
	if err != nil {
		return nil, false, err
	}
	if !p.CanManage {
		return p, false, nil
	}
	rows, err := s.Index.Rows(index.Query{EngID: p.Eng.ID})
	if err != nil {
		return nil, false, err
	}
	// Q11: only what was delivered is retested; the table lists what can be
	// picked, so its count and the ticked rows are of those
	for _, row := range rows {
		if row.Status == "complete" || row.Status == "reported" {
			p.Rows = append(p.Rows, row)
		}
	}
	return p, true, nil
}

func (s *Server) retestForm(w http.ResponseWriter, r *http.Request) {
	p, ok, err := s.retestPage(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok {
		http.Error(w, "only a director can start a retest", http.StatusForbidden)
		return
	}
	id, err := s.freeEngID(p.Eng.ID + "-retest")
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Form = map[string][]string{"id": {id}, "name": {p.Eng.Name + " — retest"}, "client": {p.Eng.Client}}
	for _, row := range p.Rows {
		p.Form["finding"] = append(p.Form["finding"], row.Dir)
	}
	p.Users = s.Auth.Users()
	s.render(w, "new_retest.html", p)
}

// freeEngID is id, else id-2, id-3 …: the first no engagement folder has
// (CreateRetest refuses an ID whose folder exists), as freeSlug is for a
// template's name.
func (s *Server) freeEngID(id string) (string, error) {
	ids, err := s.Store.EngagementIDs()
	if err != nil {
		return "", err
	}
	free := id
	for i := 2; slices.Contains(ids, free); i++ {
		free = fmt.Sprintf("%s-%d", id, i)
	}
	return free, nil
}

func (s *Server) retestCreate(w http.ResponseWriter, r *http.Request) {
	p, ok, err := s.retestPage(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !ok {
		http.Error(w, "only a director can start a retest", http.StatusForbidden)
		return
	}
	r.ParseForm()
	p.Form = r.PostForm
	e := store.Engagement{ID: strings.TrimSpace(r.FormValue("id")), Name: strings.TrimSpace(r.FormValue("name")),
		Client: strings.TrimSpace(r.FormValue("client")), Start: r.FormValue("start"), End: r.FormValue("end")}
	assignee := r.FormValue("assignee")
	if assignee != "" && !slices.ContainsFunc(s.Auth.Users(), func(x config.User) bool { return x.Username == assignee }) {
		err = fmt.Errorf("%w: unknown retester %s", store.ErrInvalidValue, assignee)
	} else {
		err = s.Store.CreateRetest(e, p.Eng.ID, r.PostForm["finding"], assignee, p.User)
	}
	if err != nil {
		// the form again, with what was typed and why it did not go through
		status, msg := http.StatusInternalServerError, "the retest could not be created; try again"
		var d *workflow.Denied
		switch {
		case errors.Is(err, store.ErrInvalidValue):
			status, msg = http.StatusBadRequest, strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": ")
		case errors.As(err, &d):
			status, msg = http.StatusForbidden, d.Reason
		case errors.Is(err, store.ErrBusy):
			status, msg = http.StatusConflict, store.ErrBusy.Error()
		default:
			s.log().Error("retest: the engagement could not be created", "eng", p.Eng.ID, "user", p.User.Username, "err", err)
		}
		p.Error, p.Users = msg, s.Auth.Users()
		// the head counts the ticked rows: drop picks no longer listed, and
		// one sent twice
		var picks []string
		for _, row := range p.Rows {
			if slices.Contains(p.Form["finding"], row.Dir) {
				picks = append(picks, row.Dir)
			}
		}
		p.Form["finding"] = picks
		s.renderStatus(w, status, "new_retest.html", p)
		return
	}
	http.Redirect(w, r, "/e/"+e.ID, http.StatusSeeOther)
}

// checkedIn is a template helper: is v among the form values for key?
func checkedIn(vals map[string][]string, key, v string) bool { return slices.Contains(vals[key], v) }
