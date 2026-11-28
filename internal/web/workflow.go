package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

type wfAction struct {
	Name                           string // the action (submit, return, clear, …)
	Label, URL, Title              string
	NeedsReason, Primary, Disabled bool
	Gated                          bool // submit/approve/complete: blocked by gate and rule errors
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
	Steps   []string // the flow's ShownSteps
	Simple  bool     // the simple workflow: its slots (wfSimpleLayout), no reviewers
	Author  string   // the one chip of the simple bar, in the reviewers' place
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
	// ReviewersBase is the list the picker's boxes were ticked from
	// (store.ReviewersHash): a save from an older list is refused.
	ReviewersBase string
	URL           string // the bar alone (live refresh)
	Seen          string // the full digest of the version shown (store.ApprovalHash): Sign off, Approve and Complete are for it
	SeenFiles     string // and the attachments shown (store.AttachmentsHash)
	Returned      *finding.Returned
	Withdrawn     *finding.Returned // who withdrew the finding and why
	IsWithdrawn   bool              // no step is current or done
	ReadOnly      bool              // the engagement is archived: no actions

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
	Running, Queued bool // Queued: the run waits for a slot (Running too)
	Busy            bool // a fix runs: Check waits (disabled)
	Done, Total     int
	Class           string // secondary, or primary when stale
	Flag, FlagClass string // slot text and its look ("" = empty slot)
	FlagN           int    // a count after the text (0 = none)
	FlagTag         bool   // the slot holds a tag (stale) rather than a chip
}

// checkOf is the bar's Check button for the checks panel v.
func checkOf(v checksView) wfCheck {
	c := wfCheck{On: v.Enabled, Show: v.Enabled && !v.ReadOnly, URL: v.URL, Running: v.Running, Queued: v.Queued, Busy: v.Fixing, Done: v.Done, Total: v.Total, Class: "secondary"}
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
	Open               bool   // the reason panel is shown: its action was just denied
	Reason             string // the reason typed before the denial
}

// wfDenial is a denied action, kept for the finding page the POST
// redirects to: the error and the typed reason come back with it.
type wfDenial struct {
	Path, Act, Reason, Error string
}

// reopen shows the denied action's reason panel again, with its reason.
func (v *wfView) reopen(d *wfDenial) {
	for _, list := range [][]wfSlot{v.Slots, v.Panels} {
		for i := range list {
			if list[i].Slot == d.Act && list[i].PanelID != "" {
				list[i].Open, list[i].Reason = true, d.Reason
			}
		}
	}
}

// wfKeys maps an action to its key (K4). A key is on the rendered button
// only, so it follows the viewer's rights; a disabled button's does nothing.
var wfKeys = map[workflow.Action]string{
	workflow.Submit: "Shift+S", workflow.Clear: "Shift+O", workflow.Approve: "Shift+A", workflow.Report: "Shift+P",
	workflow.Return: "Shift+R", workflow.Withdraw: "Shift+W", workflow.Reopen: "Shift+U", workflow.Unreport: "Shift+U",
	workflow.Revise: "Shift+U", workflow.TakeBack: "Shift+T",
	// Approve's key: Shift+A completes a finding in either workflow
	workflow.Complete: "Shift+A",
}

type wfSlotSpec struct {
	act   workflow.Action
	width string
}

// wfLayout fixes the button slots of each status, left to right. Withdraw
// is always last, so it sits at the bar's right edge in every status. Take
// back stands right before it: the author, who has no review button, sees
// the two side by side, and a reviewer's bar ends before both.
var wfLayout = map[string][]wfSlotSpec{
	"draft": {{workflow.Submit, "w112"}, {workflow.Withdraw, "w136"}},
	"verification": {{workflow.Return, "w112"}, {workflow.Clear, "w112"}, {workflow.Approve, "w112"},
		{workflow.TakeBack, "w112"}, {workflow.Withdraw, "w136"}},
	"complete":         {{workflow.Reopen, "w136"}, {workflow.Report, "w136"}, {workflow.Withdraw, "w136"}},
	"reported":         {{workflow.Unreport, "w136"}, {workflow.Withdraw, "w136"}},
	workflow.Withdrawn: {{workflow.Revise, "w136"}},
}

// wfSimpleLayout is wfLayout for the simple workflow: Complete takes
// Submit's slot; the other statuses keep theirs.
var wfSimpleLayout = map[string][]wfSlotSpec{
	"draft":            {{workflow.Complete, "w112"}, {workflow.Withdraw, "w136"}},
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
	f, layout := workflow.Flow{Simple: v.Simple}, wfLayout
	if v.Simple {
		layout = wfSimpleLayout
	}
	for _, sp := range layout[m.Status] {
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
			case sp.act == workflow.Reopen || sp.act == workflow.Unreport || sp.act == workflow.Revise || sp.act == workflow.TakeBack:
				sl.Class = "secondary"
			default:
				sl.Class = "primary"
			}
			if workflow.NeedsReason(sp.act) {
				// a reason panel under the bar; its button takes the slot's
				// class (the slot's button is wf-<slot>)
				sl.PanelID = "wf-" + name + "-reason"
				sl.PanelHead = map[workflow.Action]string{workflow.Return: "Return to draft", workflow.Withdraw: "Withdraw finding",
					workflow.Reopen: f.RevertName(workflow.Reopen), workflow.Unreport: f.RevertName(workflow.Unreport)}[sp.act]
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
	// and the ones before the first: Check sits beside it (asked after the run)
	for len(v.Slots) > 0 && !v.Slots[0].Present {
		v.Slots = v.Slots[1:]
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
	mux.Handle("POST /e/{eng}/f/{fid}/action/{act}", s.lintLived(http.HandlerFunc(s.wfAction))) // approve and complete may run every rule (Require Check off)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/reviewers", s.wfReviewers)
	mux.HandleFunc("GET /e/{eng}/f/{fid}/workflow", s.workflowBar)
}

func (s *Server) wfFor(ref store.FindingRef, r *http.Request) wfView {
	u := auth.UserFrom(r.Context())
	m := ref.F.Meta
	base := findingURL(ref.EngID, ref.Dir)
	archived := s.Store.Archived(ref.EngID)
	f := s.flow()
	v := wfView{Status: m.Status, Shown: workflow.Shown(m), Steps: f.ShownSteps(), CanAssign: f.HasReviewers() && workflow.CanAssign(u, m) && !archived,
		ReviewersURL: base + "/reviewers", ReviewersBase: store.ReviewersHash(m), URL: base + "/workflow", Seen: ref.Full, Returned: m.Returned, Withdrawn: m.Withdrawn,
		IsWithdrawn: m.Status == workflow.Withdrawn, ReadOnly: archived, Simple: f.Simple, Author: m.Author}
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
	for _, a := range f.Actions() {
		if archived || f.Check(u, m, a) != nil {
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
			s.log().Error("workflow bar: the open checks are not read", "eng", ref.EngID, "finding", ref.F.Meta.ID, "err", err)
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
			s.log().Error("workflow bar: the check gate is not read", "eng", ref.EngID, "finding", ref.F.Meta.ID, "err", gerr)
		}
		wf.NeedsCheck = gate != "" || gerr != nil
		// a sign-off covers the attachments shown too
		files, ferr := s.Store.AttachmentsHash(ref.EngID, ref.Dir)
		if ferr != nil {
			s.log().Error("workflow bar: the attachments are not read", "eng", ref.EngID, "finding", ref.F.Meta.ID, "err", ferr)
		}
		wf.SeenFiles = files
		for i, a := range wf.Actions {
			if act, _ := workflow.ParseAction(a.Name); store.SignsOff(act) && (len(open) > 0 || err != nil || wf.NeedsCheck || ferr != nil) {
				wf.Actions[i].Disabled = true
			}
		}
	}
	if errs := checks.Gate; len(errs) > 0 && wf.HasGated {
		wf.Gate = append(wf.Gate, errs...)
	}
	// D3: Approve and Complete wait while the strip counts an error: the fast
	// rules' now, or one the last run found on this content. Submit runs the
	// fast rules only (the store's Submit): it waits for their open errors
	// and for the workflow gate, not for an error a script or an AI rule left
	// in the last run. The count shown stays the strip's
	for i, a := range wf.Actions {
		if !a.Gated {
			continue
		}
		if len(checks.Gate) > 0 || (checks.Errors > 0 && a.Name != string(workflow.Submit)) {
			wf.Actions[i].Disabled = true
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

// wfBack sends the browser to the page to after a workflow action: 303 for
// a plain form, and for a form htmx sent (a reason panel) HX-Redirect, which
// loads the page (a 303 would be followed inside the request and its page
// would land in the form).
func wfBack(w http.ResponseWriter, r *http.Request, to string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *Server) wfDone(w http.ResponseWriter, r *http.Request, err error) {
	var d *workflow.Denied
	switch {
	case err == nil:
		wfBack(w, r, findingURL(r.PathValue("eng"), r.PathValue("fid")))
	case errors.As(err, &d):
		// back to the finding's own URL (a reload re-posts nothing), with the
		// error and the typed reason kept for it
		to := findingURL(r.PathValue("eng"), r.PathValue("fid"))
		// kept up to the store's cap: a reason refused for its length is not
		// parked here whole
		reason := r.FormValue("reason")
		if rs := []rune(reason); len(rs) > store.MaxReason {
			reason = string(rs[:store.MaxReason])
		}
		js, _ := json.Marshal(wfDenial{Path: to, Act: r.PathValue("act"), Reason: reason, Error: d.Reason})
		s.flash.put(r, "wfdenied", string(js))
		wfBack(w, r, to)
	case errors.Is(err, store.ErrBusy) && r.Header.Get("HX-Request") == "true":
		// htmx swaps a 409 without a word and the reason form swaps nothing:
		// 422 is shown as a toast, and the reason stays in its box
		http.Error(w, store.ErrBusy.Error(), http.StatusUnprocessableEntity)
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
	// Sign off and Approve are for the version the page showed (its hash and
	// its attachments)
	err := s.Store.TransitionSeen(ref.EngID, ref.Dir, act, r.FormValue("reason"), r.FormValue("seen"), r.FormValue("seenfiles"), auth.UserFrom(r.Context()))
	s.wfDone(w, r, err)
}

func (s *Server) wfReviewers(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	r.ParseForm()
	names := r.PostForm["reviewer"]
	if !s.flow().HasReviewers() {
		// no one to name: the store refuses any list, before a name is judged
		s.wfDone(w, r, s.Store.SetReviewers(ref.EngID, ref.Dir, names, auth.UserFrom(r.Context())))
		return
	}
	users := s.Auth.Users() // once per request, not per name
	if r.PostForm.Get("all") != "" {
		// add every reviewer-role account to the list as it is inside the
		// change: whoever is assigned stays, also someone added since the
		// page was read, and a director author's own sign-off (Q25)
		names = nil
		for _, c := range users {
			if c.Role == "reviewer" && s.Store.CanReview(c, ref.EngID, ref.F.Meta) {
				names = append(names, c.Username)
			}
		}
		if len(names) == 0 { // nobody to add: the list stays
			s.wfDone(w, r, nil)
			return
		}
		s.wfDone(w, r, s.Store.AddReviewers(ref.EngID, ref.Dir, names, auth.UserFrom(r.Context())))
		return
	}
	for _, n := range names {
		ok := slices.ContainsFunc(users, func(c config.User) bool {
			return c.Username == n && s.Store.CanReview(c, ref.EngID, ref.F.Meta)
		})
		if !ok { // back to the finding's page, as every refusal here
			s.wfDone(w, r, &workflow.Denied{Reason: "unknown or ineligible reviewer " + n})
			return
		}
	}
	// the ticked names are the list as the page read it: a list changed
	// since is refused, not replaced
	s.wfDone(w, r, s.Store.SetReviewersFrom(ref.EngID, ref.Dir, r.PostForm.Get("base"), names, auth.UserFrom(r.Context())))
}
