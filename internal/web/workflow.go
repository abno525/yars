package web

import (
	"errors"
	"net/http"
	"slices"

	"yars/internal/auth"
	"yars/internal/finding"
	"yars/internal/store"
	"yars/internal/workflow"
)

type wfAction struct {
	Label, URL                     string
	NeedsReason, Primary, Disabled bool
	Gated                          bool // submit/approve: blocked by gate and rule errors
}

type wfReviewer struct {
	Name    string
	Cleared bool
}

type wfCandidate struct {
	Name    string
	Checked bool
}

type wfView struct {
	Status       string
	Steps        []string
	Actions      []wfAction
	Gate         []string
	Reviewers    []wfReviewer
	Candidates   []wfCandidate
	CanAssign    bool
	HasGated     bool
	ReviewersURL string
	Returned     *finding.Returned
}

func (s *Server) routesWorkflow(mux *http.ServeMux) {
	mux.HandleFunc("POST /e/{eng}/f/{fid}/action/{act}", s.wfAction)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/reviewers", s.wfReviewers)
}

func (s *Server) wfFor(ref store.FindingRef, r *http.Request) wfView {
	u := auth.UserFrom(r.Context())
	m := ref.F.Meta
	base := "/e/" + ref.EngID + "/f/" + ref.Dir
	v := wfView{Status: m.Status, Steps: workflow.Statuses, CanAssign: workflow.CanAssign(u, m),
		ReviewersURL: base + "/reviewers", Returned: m.Returned}
	for _, n := range m.Reviewers {
		v.Reviewers = append(v.Reviewers, wfReviewer{Name: n, Cleared: slices.Contains(m.ClearedBy, n)})
	}
	if v.CanAssign {
		for _, c := range s.Auth.Users() {
			if workflow.ReviewerCandidate(c, m) {
				v.Candidates = append(v.Candidates, wfCandidate{Name: c.Username, Checked: slices.Contains(m.Reviewers, c.Username)})
			}
		}
	}
	for _, a := range workflow.Actions {
		if a == workflow.Report || workflow.Check(u, m, a) != nil {
			continue
		}
		act := wfAction{Label: workflow.Label(a), URL: base + "/action/" + string(a),
			NeedsReason: a == workflow.Return, Primary: a != workflow.Return}
		if workflow.Gated(a) {
			act.Gated, v.HasGated = true, true
			if v.Gate = workflow.Gate(m, s.Cfg); len(v.Gate) > 0 {
				act.Disabled = true
			}
		}
		v.Actions = append(v.Actions, act)
	}
	return v
}

// allowEdit answers 403 when the user may not change the finding's content.
func (s *Server) allowEdit(w http.ResponseWriter, r *http.Request, ref store.FindingRef) bool {
	if workflow.CanEdit(auth.UserFrom(r.Context()), ref.F.Meta) {
		return true
	}
	http.Error(w, "this finding is "+ref.F.Meta.Status+"; only a director can edit it", http.StatusForbidden)
	return false
}

func (s *Server) wfDone(w http.ResponseWriter, r *http.Request, err error) {
	var d *workflow.Denied
	switch {
	case err == nil:
		http.Redirect(w, r, "/e/"+r.PathValue("eng")+"/f/"+r.PathValue("fid"), http.StatusSeeOther)
	case errors.As(err, &d):
		s.renderFinding(w, r, http.StatusBadRequest, d.Reason)
	default:
		s.fail(w, err)
	}
}

func (s *Server) wfAction(w http.ResponseWriter, r *http.Request) {
	act := workflow.Action(r.PathValue("act"))
	if !slices.Contains(workflow.Actions, act) || act == workflow.Report {
		s.renderFinding(w, r, http.StatusBadRequest, "unknown action")
		return
	}
	err := s.Store.Transition(r.PathValue("eng"), r.PathValue("fid"), act, r.FormValue("reason"), auth.UserFrom(r.Context()))
	s.wfDone(w, r, err)
}

func (s *Server) wfReviewers(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	names := r.PostForm["reviewer"]
	for _, n := range names {
		ok := false
		for _, c := range s.Auth.Users() {
			if c.Username == n && workflow.ReviewerCandidate(c, ref.F.Meta) {
				ok = true
			}
		}
		if !ok {
			s.renderFinding(w, r, http.StatusBadRequest, "unknown or ineligible reviewer "+n)
			return
		}
	}
	s.wfDone(w, r, s.Store.SetReviewers(ref.EngID, ref.Dir, names, auth.UserFrom(r.Context())))
}
