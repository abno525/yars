package web

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/index"
	"yars/internal/store"
	"yars/internal/workflow"
)

type retestOption struct {
	Code, Label string
	Checked     bool
}

type retestView struct {
	Result, Source, SourceURL string
	SourceStatus, SourceSev   string
	SourceMissing             bool
	Options                   []retestOption
	URL, Error                string
	Locked                    bool
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
	if eng, dir, ok := strings.Cut(rt.Source, "/"); ok {
		v.SourceURL = findingURL(eng, dir)
		if src, err := s.Store.Finding(eng, dir); err == nil {
			v.SourceStatus = src.F.Meta.Status
			v.SourceSev = src.F.Meta.Severity
		} else {
			v.SourceMissing = true
		}
	}
	for _, c := range workflow.RetestResults {
		v.Options = append(v.Options, retestOption{Code: c, Label: workflow.RetestLabel(c), Checked: c == rt.Result})
	}
	return v
}

func (s *Server) retestSave(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.editRef(w, r)
	if !ok {
		return
	}
	err := s.Store.SetRetestResult(ref.EngID, ref.Dir, r.FormValue("result"), auth.UserFrom(r.Context()))
	if err != nil && !errors.Is(err, store.ErrInvalidValue) {
		s.fail(w, err)
		return
	}
	status := http.StatusOK
	if err == nil {
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
	if err != nil {
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
	if p.Rows, err = s.Index.Rows(index.Query{EngID: p.Eng.ID}); err != nil {
		return nil, false, err
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
	p.Form = map[string][]string{"id": {p.Eng.ID + "-retest"}, "name": {p.Eng.Name + " — retest"}, "client": {p.Eng.Client}}
	for _, row := range p.Rows {
		if row.Status == "complete" || row.Status == "reported" {
			p.Form["finding"] = append(p.Form["finding"], row.Dir)
		}
	}
	p.Users = s.Auth.Users()
	s.render(w, "new_retest.html", p)
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
	if errors.Is(err, store.ErrInvalidValue) {
		p.Error = strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": ")
		p.Users = s.Auth.Users()
		s.renderStatus(w, http.StatusBadRequest, "new_retest.html", p)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/e/"+e.ID, http.StatusSeeOther)
}

// checkedIn is a template helper: is v among the form values for key?
func checkedIn(vals map[string][]string, key, v string) bool { return slices.Contains(vals[key], v) }
