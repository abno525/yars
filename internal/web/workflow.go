package web

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/finding"
	"yars/internal/store"
	"yars/internal/workflow"
)

type wfAction struct {
	Name                           string // the action (submit, return, clear, …)
	Label, URL, Title              string
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
	Withdrawn    *finding.Returned // who withdrew the finding and why
	IsWithdrawn  bool              // no step is current or done
	ReadOnly     bool              // the engagement is archived: no actions

	// The bar as drawn: the first chips, how many more, the fixed button
	// slots of the status, the reason forms they open and the state text.
	Chips      []wfReviewer
	More       int
	Slots      []wfSlot
	Panels     []wfSlot
	State      string
	StateError bool
}

// wfSlot is one fixed place in the button row. Present is false when the
// viewer may not take the action: an empty slot of the same width is drawn.
type wfSlot struct {
	wfAction
	Slot, Width, Class string
	Present            bool
	PanelID, PanelHead string // a reason form under the bar (Return, Withdraw)
}

type wfSlotSpec struct {
	act   workflow.Action
	width string
}

// wfLayout fixes the button slots of each status, left to right.
var wfLayout = map[string][]wfSlotSpec{
	"draft":            {{workflow.Withdraw, "w136"}, {workflow.Submit, "w112"}},
	"verification":     {{workflow.Withdraw, "w136"}, {workflow.Return, "w112"}, {workflow.Clear, "w112"}, {workflow.Approve, "w112"}},
	"complete":         {{workflow.Withdraw, "w136"}, {workflow.Reopen, "w136"}, {workflow.Report, "w136"}},
	"reported":         {{workflow.Withdraw, "w136"}},
	workflow.Withdrawn: {{workflow.Revise, "w136"}},
}

// barLabel is the short button label; the full label is its title.
func barLabel(a workflow.Action) string {
	switch a {
	case workflow.Submit:
		return "Submit"
	case workflow.Return:
		return "Return"
	}
	return workflow.Label(a)
}

const wfChips = 3 // reviewer chips shown before "+N"

// arrange lays the actions out in the status's fixed slots and sets the
// state text. Run it after gating.
func (v *wfView) arrange(u config.User, m finding.Meta) {
	if len(v.Reviewers) > wfChips {
		v.Chips, v.More = v.Reviewers[:wfChips], len(v.Reviewers)-wfChips
	} else {
		v.Chips = v.Reviewers
	}
	have := map[string]wfAction{}
	for _, a := range v.Actions {
		have[a.Name] = a
	}
	director := workflow.AtLeast(u, "director")
	signed := slices.Contains(m.ClearedBy, u.Username)
	var needsSignOff bool
	base := strings.TrimSuffix(v.URL, "/workflow") + "/action/"
	for _, sp := range wfLayout[m.Status] {
		name := string(sp.act)
		sl := wfSlot{Slot: name, Width: sp.width}
		sl.URL = base + name
		if a, ok := have[name]; ok {
			sl.wfAction, sl.Present = a, true
		} else if m.Status == "verification" && !v.ReadOnly {
			// kept in place, disabled: an earlier sign-off, or Approve
			// waiting for one
			switch {
			case sp.act == workflow.Clear && signed && (director || slices.Contains(m.Reviewers, u.Username)):
				sl.wfAction = wfAction{Name: name, Label: workflow.Label(sp.act), URL: sl.URL, Disabled: true}
				sl.Present = true
			case sp.act == workflow.Approve && director:
				sl.wfAction = wfAction{Name: name, Label: workflow.Label(sp.act), URL: sl.URL, Disabled: true}
				sl.Present, needsSignOff = true, true
			}
		}
		if sl.Present {
			sl.Title = sl.Label
			sl.Label = barLabel(sp.act)
			switch {
			case workflow.NeedsReason(sp.act):
				sl.Class = "danger"
				sl.PanelID = "wf-" + name
				sl.PanelHead = map[workflow.Action]string{workflow.Return: "Return to draft", workflow.Withdraw: "Withdraw finding"}[sp.act]
				v.Panels = append(v.Panels, sl)
			case sp.act == workflow.Reopen || sp.act == workflow.Revise:
				sl.Class = "secondary"
			default:
				sl.Class = "primary"
			}
		}
		v.Slots = append(v.Slots, sl)
	}
	switch n := len(v.Gate); {
	case n > 0 && v.HasGated:
		v.State, v.StateError = plural(n, "error")+" to fix", true
	case needsSignOff:
		v.State = "Needs 1 sign-off"
	case m.Status == "verification" && signed:
		v.State = "Signed off"
	case m.Status == "verification" && u.Username == m.Author:
		v.State = "Own finding"
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
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
	archived := s.Store.Archived(ref.EngID)
	v := wfView{Status: m.Status, Steps: workflow.Statuses, CanAssign: workflow.CanAssign(u, m) && !archived,
		ReviewersURL: base + "/reviewers", URL: base + "/workflow", Returned: m.Returned, Withdrawn: m.Withdrawn,
		IsWithdrawn: m.Status == workflow.Withdrawn, ReadOnly: archived}
	if v.IsWithdrawn {
		v.Returned = nil // the withdrawal is what counts now
	}
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
		if archived || workflow.Check(u, m, a) != nil {
			continue
		}
		act := wfAction{Name: string(a), Label: workflow.Label(a), URL: base + "/action/" + string(a),
			NeedsReason: workflow.NeedsReason(a), Primary: !workflow.NeedsReason(a)}
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
// errors (unless dismissed) also block submit and approve. It returns the
// checks panel it built.
func (s *Server) wfGated(r *http.Request, ref store.FindingRef) (wfView, checksView) {
	checks := s.checksFor(r, ref)
	wf := s.wfFor(ref, r)
	if errs := checks.Gate; len(errs) > 0 {
		for i, a := range wf.Actions {
			if a.Gated {
				wf.Actions[i].Disabled = true
			}
		}
		if wf.HasGated {
			wf.Gate = append(wf.Gate, errs...)
		}
	}
	wf.arrange(auth.UserFrom(r.Context()), ref.F.Meta)
	return wf, checks
}

// allowEdit answers 403 when the user may not change the finding's content.
func (s *Server) allowEdit(w http.ResponseWriter, r *http.Request, ref store.FindingRef) bool {
	if s.Store.Archived(ref.EngID) {
		http.Error(w, store.ErrArchived.Error(), http.StatusForbidden)
		return false
	}
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
	act, ok := workflow.ParseAction(r.PathValue("act"))
	if !ok {
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
