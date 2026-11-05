package web

import (
	"errors"
	"net/http"
	"slices"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/finding"
	"yars/internal/rules"
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
	URL          string // the bar alone (live refresh)
	Returned     *finding.Returned
}

func (s *Server) routesWorkflow(mux *http.ServeMux) {
	mux.HandleFunc("POST /e/{eng}/f/{fid}/action/{act}", s.wfAction)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/reviewers", s.wfReviewers)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/workflow", s.workflowBar)
}

func (s *Server) wfFor(ref store.FindingRef, r *http.Request) wfView {
	u := auth.UserFrom(r.Context())
	m := ref.F.Meta
	base := findingURL(ref.EngID, ref.Dir)
	v := wfView{Status: m.Status, Steps: workflow.Statuses, CanAssign: workflow.CanAssign(u, m),
		ReviewersURL: base + "/reviewers", URL: base + "/workflow", Returned: m.Returned}
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

// wfGated is the workflow bar with the fast style rules applied: their
// errors also block submit and approve. It returns the checks it ran.
func (s *Server) wfGated(r *http.Request, ref store.FindingRef) (wfView, checksView) {
	checks := s.checksFor(r, ref, rules.Fast)
	wf := s.wfFor(ref, r)
	if errs := rules.Errors(checks.Items); len(errs) > 0 {
		for i, a := range wf.Actions {
			if a.Gated {
				wf.Actions[i].Disabled = true
			}
		}
		if wf.HasGated {
			wf.Gate = append(wf.Gate, errs...)
		}
	}
	return wf, checks
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
		http.Redirect(w, r, findingURL(r.PathValue("eng"), r.PathValue("fid")), http.StatusSeeOther)
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
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	err := s.Store.Transition(ref.EngID, ref.Dir, act, r.FormValue("reason"), auth.UserFrom(r.Context()))
	s.wfDone(w, r, err)
}

func (s *Server) wfReviewers(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	names := r.PostForm["reviewer"]
	users := s.Auth.Users() // once per request, not per name
	if r.PostForm.Get("all") != "" {
		// keep whoever is assigned and add every reviewer-role account
		names = slices.Clone(ref.F.Meta.Reviewers)
		for _, c := range users {
			if c.Role == "reviewer" && workflow.ReviewerCandidate(c, ref.F.Meta) && !slices.Contains(names, c.Username) {
				names = append(names, c.Username)
			}
		}
	}
	for _, n := range names {
		ok := slices.ContainsFunc(users, func(c config.User) bool {
			return c.Username == n && workflow.ReviewerCandidate(c, ref.F.Meta)
		})
		if !ok {
			s.renderFinding(w, r, http.StatusBadRequest, "unknown or ineligible reviewer "+n)
			return
		}
	}
	s.wfDone(w, r, s.Store.SetReviewers(ref.EngID, ref.Dir, names, auth.UserFrom(r.Context())))
}
