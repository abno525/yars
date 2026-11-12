package web

import (
	"errors"
	"log"
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
	Status  string
	Shown   string   // the current step: Status, or signed off (workflow.Shown)
	Steps   []string // workflow.ShownSteps
	Actions []wfAction
	Gate    []string
	// open check errors and warnings keeping Sign off or Approve disabled
	OpenErrors, OpenWarnings int
	// Problems: the Checks strip's Errors count, shown as "N errors to fix"
	// to a viewer who may submit or approve, and as "N errors open" to one
	// who signs off (D3: one count)
	Problems int
	// Require Check: Sign off and Approve wait for a check run on this content
	NeedsCheck   bool
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
	Check      wfCheck // the Check button and its state slot

	// Refetch: the bar answers a started check; it fetches itself again once
	// swapped in, since check events may have come before it was
	Refetch bool
}

// wfCheck is the Check button of the bar (152 px) and the slot before it:
// stale checks, a rule that failed, AI checks that failed, rule file errors.
type wfCheck struct {
	On, Show        bool // checks configured; the button is shown (not archived)
	URL             string
	Running         bool
	Busy            bool // a fix runs: Check waits (disabled)
	Done, Total     int
	Class           string // secondary, or primary when stale
	Flag, FlagClass string // slot text and its look ("" = empty slot)
	FlagN           int    // a count after the text (0 = none)
	FlagTag         bool   // the slot holds a tag (stale) rather than a chip
}

// checkOf is the bar's Check button for the checks panel v.
func checkOf(v checksView) wfCheck {
	c := wfCheck{On: v.Enabled, Show: v.Enabled && !v.ReadOnly, URL: v.URL, Running: v.Running, Busy: v.Fixing, Done: v.Done, Total: v.Total, Class: "secondary"}
	failed := 0
	for _, x := range v.Steps {
		if x.State == "failed" {
			failed++
		}
	}
	switch {
	case v.Running:
	case v.State == "stale":
		c.Class, c.Flag, c.FlagTag = "primary", "Checks stale", true
	case v.ConfigErrors > 0:
		c.Flag, c.FlagClass = plural(v.ConfigErrors, "config error"), "bad text"
	case failed > 0:
		c.Flag, c.FlagClass, c.FlagN = "Rule failed", "bad", failed
	case len(v.AIFailed) > 0:
		c.Flag, c.FlagClass, c.FlagN = "AI checks failed", "warn", len(v.AIFailed)
	}
	return c
}

// wfSlot is one fixed place in the button row. Present is false when the
// viewer may not take the action: an empty slot of the same width is drawn.
type wfSlot struct {
	wfAction
	Slot, Width, Class string
	Present            bool
	DescribedBy        string // the id of the state text saying why it is disabled
	PanelID, PanelHead string // a reason form under the bar (Return, Withdraw, the reverts)
	Key                string // aria-keyshortcuts of the button ("" = none)
}

// wfKeys maps an action to its key (K4). A key is on the rendered button
// only, so it follows the viewer's rights; a disabled button's does nothing.
var wfKeys = map[workflow.Action]string{
	workflow.Submit: "Shift+S", workflow.Clear: "Shift+O", workflow.Approve: "Shift+A", workflow.Report: "Shift+P",
	workflow.Return: "Shift+R", workflow.Withdraw: "Shift+W", workflow.Reopen: "Shift+U", workflow.Unreport: "Shift+U",
	workflow.Revise: "Shift+U", workflow.TakeBack: "Shift+T",
}

type wfSlotSpec struct {
	act   workflow.Action
	width string
}

// wfLayout fixes the button slots of each status, left to right. Withdraw
// is always last, so it sits at the bar's right edge in every status.
var wfLayout = map[string][]wfSlotSpec{
	"draft":            {{workflow.Submit, "w112"}, {workflow.Withdraw, "w136"}},
	"verification":     {{workflow.Return, "w112"}, {workflow.Clear, "w112"}, {workflow.Approve, "w112"}, {workflow.Withdraw, "w136"}},
	"complete":         {{workflow.Reopen, "w136"}, {workflow.Report, "w136"}, {workflow.Withdraw, "w136"}},
	"reported":         {{workflow.Unreport, "w136"}, {workflow.Withdraw, "w136"}},
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
			sl.Key = wfKeys[sp.act]
			switch {
			case sp.act == workflow.Return || sp.act == workflow.Withdraw:
				sl.Class = "danger"
			case sp.act == workflow.Reopen || sp.act == workflow.Unreport || sp.act == workflow.Revise:
				sl.Class = "secondary"
			default:
				sl.Class = "primary"
			}
			if workflow.NeedsReason(sp.act) {
				// a reason panel under the bar; its button takes the slot's
				// class (the slot's button is wf-<slot>)
				sl.PanelID = "wf-" + name + "-reason"
				sl.PanelHead = map[workflow.Action]string{workflow.Return: "Return to draft", workflow.Withdraw: "Withdraw finding",
					workflow.Reopen: "Revert to verification", workflow.Unreport: "Revert to complete"}[sp.act]
				if sp.act == workflow.Reopen || sp.act == workflow.Unreport {
					sl.Title = sl.PanelHead // both read "Revert": the title says which
				}
				v.Panels = append(v.Panels, sl)
			}
		}
		v.Slots = append(v.Slots, sl)
	}
	// the viewer's last button ends at the right edge (under Export): the
	// slots after it are ones this viewer never fills here
	for len(v.Slots) > 0 && !v.Slots[len(v.Slots)-1].Present {
		v.Slots = v.Slots[:len(v.Slots)-1]
	}
	switch {
	case v.Problems > 0 && v.HasGated:
		v.State, v.StateError = plural(v.Problems, "error")+" to fix", true
	case v.OpenErrors > 0:
		// the strip's count where it lists them (D3: one count)
		n := v.OpenErrors
		if v.Problems > 0 {
			n = v.Problems
		}
		v.State, v.StateError = plural(n, "error")+" open", true
	case v.OpenWarnings > 0:
		v.State = plural(v.OpenWarnings, "warning") + " open"
	case v.NeedsCheck:
		v.State = store.GateLabel
	case needsSignOff:
		v.State = "Needs 1 sign-off"
	case m.Status == "verification" && u.Username == m.Author:
		v.State = "Own finding"
	}
	// a disabled Sign off or Approve is described by the state: why it waits
	for i, sl := range v.Slots {
		if act, _ := workflow.ParseAction(sl.Name); sl.Present && sl.Disabled && store.SignsOff(act) && v.State != "" {
			v.Slots[i].DescribedBy = "wf-state"
		}
	}
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

func (s *Server) routesWorkflow(mux *http.ServeMux) {
	mux.Handle("POST /e/{eng}/f/{fid}/action/{act}", s.lintLived(http.HandlerFunc(s.wfAction))) // submit and approve run every rule
	mux.HandleFunc("POST /e/{eng}/f/{fid}/reviewers", s.wfReviewers)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/workflow", s.workflowBar)
}

func (s *Server) wfFor(ref store.FindingRef, r *http.Request) wfView {
	u := auth.UserFrom(r.Context())
	m := ref.F.Meta
	base := findingURL(ref.EngID, ref.Dir)
	archived := s.Store.Archived(ref.EngID)
	v := wfView{Status: m.Status, Shown: workflow.Shown(m), Steps: workflow.ShownSteps, CanAssign: workflow.CanAssign(u, m) && !archived,
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
			if s.Store.CanReview(c, ref.EngID, m) {
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
			if v.Gate = workflow.Gate(m, s.conf()); len(v.Gate) > 0 {
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
	// a director gets clean findings only: any open check (warnings too)
	// keeps Sign off and Approve disabled until it is fixed or dismissed
	// (the store's own source: Store.OpenChecks)
	signs := slices.ContainsFunc(wf.Actions, func(a wfAction) bool {
		act, _ := workflow.ParseAction(a.Name)
		return store.SignsOff(act)
	})
	if signs {
		open, err := s.Store.OpenChecks(ref.EngID, ref.Dir)
		if err != nil {
			log.Printf("open checks of %s/%s: %v", ref.EngID, ref.Dir, err)
		}
		for _, v := range open {
			if v.Level == "warning" {
				wf.OpenWarnings++
			} else {
				wf.OpenErrors++
			}
		}
		// Require Check: a finished run on this content first (the store's
		// own gate)
		gate, gerr := s.Store.CheckGate(ref.EngID, ref.Dir)
		if gerr != nil {
			log.Printf("check gate of %s/%s: %v", ref.EngID, ref.Dir, gerr)
		}
		wf.NeedsCheck = gate != "" || gerr != nil
		for i, a := range wf.Actions {
			if act, _ := workflow.ParseAction(a.Name); store.SignsOff(act) && (len(open) > 0 || err != nil || wf.NeedsCheck) {
				wf.Actions[i].Disabled = true
			}
		}
	}
	if errs := checks.Gate; len(errs) > 0 && wf.HasGated {
		wf.Gate = append(wf.Gate, errs...)
	}
	// D3: Submit and Approve wait while the strip counts an error: the fast
	// rules' now, or one the last run found on this content (they run every
	// rule)
	if len(checks.Gate) > 0 || checks.Errors > 0 {
		for i, a := range wf.Actions {
			if a.Gated {
				wf.Actions[i].Disabled = true
			}
		}
	}
	wf.Problems = checks.Errors
	if !checks.Enabled && wf.HasGated { // no rules, no strip: the gate's own count
		wf.Problems = len(wf.Gate)
	}
	wf.arrange(auth.UserFrom(r.Context()), ref.F.Meta)
	wf.Check = checkOf(checks)
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
			if c.Role == "reviewer" && s.Store.CanReview(c, ref.EngID, ref.F.Meta) && !slices.Contains(names, c.Username) {
				names = append(names, c.Username)
			}
		}
	}
	for _, n := range names {
		ok := slices.ContainsFunc(users, func(c config.User) bool {
			return c.Username == n && s.Store.CanReview(c, ref.EngID, ref.F.Meta)
		})
		if !ok {
			s.renderFinding(w, r, http.StatusBadRequest, "unknown or ineligible reviewer "+n)
			return
		}
	}
	s.wfDone(w, r, s.Store.SetReviewers(ref.EngID, ref.Dir, names, auth.UserFrom(r.Context())))
}
