// Package workflow holds the status/role rules shared by the web UI, the
// git pre-receive check and the MCP server.
package workflow

import (
	"fmt"
	"slices"
	"strings"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/cvss"
	"github.com/abno525/yars/internal/finding"
)

type Action string

const (
	Submit  Action = "submit"
	Return  Action = "return"
	Clear   Action = "clear"
	Approve Action = "approve"
	Reopen  Action = "reopen"
	Report  Action = "report"
	// Withdraw takes a finding out of the report (reason required);
	// Revise brings a withdrawn finding back as a draft.
	Withdraw Action = "withdraw"
	Revise   Action = "revise"
	// TakeBack is the author (or a director) pulling a finding in
	// verification back to draft, without a reason.
	TakeBack Action = "take_back"
	// Unreport takes a reported finding back to complete (reason required);
	// with Reopen (complete back to verification) it is labelled Revert.
	Unreport Action = "unreport"
)

var Actions = []Action{Submit, Return, Clear, Approve, Reopen, Report, Unreport, Withdraw, Revise, TakeBack}

// RevertOf is the action that takes a finding in status back one step:
// complete to verification (Reopen), reported to complete (Unreport).
func RevertOf(status string) (Action, bool) {
	switch status {
	case "complete":
		return Reopen, true
	case "reported":
		return Unreport, true
	}
	return "", false
}

// aliases are other accepted names of actions.
var aliases = map[string]Action{"sign_off": Clear}

// ParseAction reads an action name (case-insensitive, aliases accepted:
// sign_off is clear). It knows the actions of both workflows (Complete
// too); whether the data folder's flow has one is Flow.Check's call.
func ParseAction(s string) (Action, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if a, ok := aliases[s]; ok {
		return a, true
	}
	a := Action(s)
	return a, slices.Contains(Actions, a) || a == Complete
}

// Withdrawn is the status of a finding taken out of the report.
const Withdrawn = "withdrawn"

// Statuses are the workflow steps in order.
var Statuses = []string{"draft", "verification", "complete", "reported"}

// AllStatuses are the steps plus withdrawn.
var AllStatuses = append(slices.Clone(Statuses), Withdrawn)

// Active reports whether a finding with this status counts in the report
// (every status except withdrawn).
func Active(status string) bool { return status != Withdrawn }

// NeedsReason reports whether an action requires a reason: Return,
// Withdraw and both reverts.
func NeedsReason(a Action) bool { return a == Return || a == Withdraw || a == Reopen || a == Unreport }

// Denied explains why an action is not allowed. Err, when set, says what
// kind of refusal it also is (a change that raced it is store.ErrConflict:
// the caller may retry).
type Denied struct {
	Reason string
	Err    error
}

func (d *Denied) Error() string { return d.Reason }

func (d *Denied) Unwrap() error { return d.Err }

func deny(format string, a ...any) error { return &Denied{Reason: fmt.Sprintf(format, a...)} }

// Target returns the statuses an action is possible in and the status it
// produces, in the standard workflow (Flow{}.Target).
func Target(a Action) (from []string, to string) { return Flow{}.Target(a) }

// standardTarget is Target of the standard workflow.
func standardTarget(a Action) (from []string, to string) {
	switch a {
	case Submit:
		return []string{"draft"}, "verification"
	case Return:
		return []string{"verification"}, "draft"
	case Clear:
		return []string{"verification"}, "verification"
	case Approve:
		return []string{"verification"}, "complete"
	case Reopen:
		return []string{"complete"}, "verification"
	case Report:
		return []string{"complete"}, "reported"
	case Unreport:
		return []string{"reported"}, "complete"
	case Withdraw:
		return []string{"draft", "verification", "complete", "reported"}, Withdrawn
	case Revise:
		return []string{Withdrawn}, "draft"
	case TakeBack:
		return []string{"verification"}, "draft"
	}
	return nil, ""
}

func Label(a Action) string {
	return map[Action]string{Submit: "Submit for verification", Return: "Return to draft", Clear: "Sign off",
		Approve: "Approve", Reopen: "Revert", Report: "Mark reported", Unreport: "Revert", Withdraw: "Withdraw", Revise: "Restore",
		TakeBack: "Take back", Complete: "Complete"}[a]
}

// AtLeast reports whether u's role is role or a stronger one. Roles only add
// power, in the order of config.Roles: pentester < reviewer < director.
func AtLeast(u config.User, role string) bool {
	have, want := slices.Index(config.Roles, u.Role), slices.Index(config.Roles, role)
	return have >= 0 && want >= 0 && have >= want
}

func manager(u config.User) bool { return AtLeast(u, "director") }

func reviewer(u config.User, m finding.Meta) bool { return slices.Contains(m.Reviewers, u.Username) }

// Check reports whether u may perform a on a finding with meta m, in the
// standard workflow (Flow{}.Check).
func Check(u config.User, m finding.Meta, a Action) error { return Flow{}.Check(u, m, a) }

// Allowed is one action as u could take it now on m.
type Allowed struct {
	Action  string `json:"action"`
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason,omitempty"` // why not, when disabled
	Needs   string `json:"needs,omitempty"`  // "reason" when the action takes one
}

// AllowedActions lists every action of cfg's workflow possible in m's
// status, in the flow's order (Flow.Actions), with whether u may take it
// (CheckWithGate: the role, the status and the content gate) and, if not,
// why.
func AllowedActions(u config.User, m finding.Meta, cfg config.Config) []Allowed {
	var out []Allowed
	f := FlowOf(cfg)
	for _, a := range f.Actions() {
		if from, _ := f.Target(a); !slices.Contains(from, m.Status) {
			continue
		}
		al := Allowed{Action: string(a), Enabled: true}
		if NeedsReason(a) {
			al.Needs = "reason"
		}
		if err := CheckWithGate(u, m, a, cfg); err != nil {
			al.Enabled, al.Reason = false, err.Error()
		}
		out = append(out, al)
	}
	return out
}

// reviewedByOther reports whether an assigned reviewer other than u cleared m.
func reviewedByOther(u config.User, m finding.Meta) bool {
	for _, c := range m.ClearedBy {
		if c != u.Username && slices.Contains(m.Reviewers, c) {
			return true
		}
	}
	return false
}

// Gated reports whether an action must also pass Gate (content
// completeness): Submit, Approve and Complete.
func Gated(a Action) bool { return a == Submit || a == Approve || a == Complete }

// CheckWithGate is the Check of cfg's workflow (FlowOf) plus, for submit,
// approve and complete, the content Gate.
func CheckWithGate(u config.User, m finding.Meta, a Action, cfg config.Config) error {
	if err := FlowOf(cfg).Check(u, m, a); err != nil {
		return err
	}
	if Gated(a) {
		if p := Gate(m, cfg); len(p) > 0 {
			return deny("cannot %s: %s", strings.ToLower(Label(a)), strings.Join(p, "; "))
		}
	}
	return nil
}

// Gate lists what blocks a draft from being submitted, approved or
// completed (empty = ready). The simple workflow has no reviewers to
// assign.
func Gate(m finding.Meta, cfg config.Config) []string {
	var p []string
	if len(m.Reviewers) == 0 && !cfg.Simple() {
		p = append(p, "assign at least one reviewer")
	}
	if strings.TrimSpace(m.Title) == "" {
		p = append(p, "the title is empty")
	}
	if m.Retest != nil && !slices.Contains(RetestResults, m.Retest.Result) {
		p = append(p, "set the retest result (fixed, not fixed or partially fixed)")
	}
	v, err := cvss.Parse(m.CVSS)
	if err != nil && strings.TrimSpace(m.Severity) == "" {
		p = append(p, "set a CVSS vector or a severity")
	}
	if err == nil {
		for _, mt := range cvss.Metrics {
			if cfg.NonStandard(mt.Key, v[mt.Key]) && strings.TrimSpace(m.CVSSReasons[mt.Key]) == "" {
				p = append(p, "explain the non-standard CVSS value for "+mt.Name)
			}
		}
	}
	return p
}

// RetestResults are the valid outcomes of a retested finding.
var RetestResults = []string{"fixed", "not_fixed", "partially_fixed"}

func RetestLabel(r string) string {
	return map[string]string{"fixed": "Fixed", "not_fixed": "Not fixed", "partially_fixed": "Partially fixed"}[r]
}

// CanEdit reports whether u may change the finding's content.
func CanEdit(u config.User, m finding.Meta) bool {
	if m.Status == "complete" || m.Status == "reported" || m.Status == Withdrawn {
		return manager(u)
	}
	return true
}

// CanAssign reports whether u may change the reviewer list (add and remove):
// the author or a director, while the finding is open.
func CanAssign(u config.User, m finding.Meta) bool {
	if m.Status != "draft" && m.Status != "verification" {
		return false
	}
	return u.Username == m.Author || manager(u)
}

// CanAddReviewers reports whether u may add reviewers without removing any:
// whoever may assign, and any reviewer, while the finding is open. Removing
// a reviewer (one who signed off, say) stays with CanAssign.
func CanAddReviewers(u config.User, m finding.Meta) bool {
	if m.Status != "draft" && m.Status != "verification" {
		return false
	}
	return CanAssign(u, m) || AtLeast(u, "reviewer")
}

// CanAddReviewer reports whether u may add name to m's reviewers: whoever
// may assign adds anyone; another reviewer adds others but never themselves,
// so someone else always chooses who reviews (four eyes).
func CanAddReviewer(u config.User, m finding.Meta, name string) bool {
	if CanAssign(u, m) {
		return true
	}
	return CanAddReviewers(u, m) && name != u.Username
}

// ReviewerCandidate reports whether u may be assigned as a reviewer of m.
func ReviewerCandidate(u config.User, m finding.Meta) bool {
	return AtLeast(u, "reviewer") && u.Username != m.Author
}

// Inbox names an inbox queue.
type Inbox string

const (
	InboxNone     Inbox = ""
	InboxNotes    Inbox = "notes"    // 1 Notifications
	InboxReturned Inbox = "returned" // 2 Returned to me
	InboxReview   Inbox = "review"   // 3 Awaiting my review
	InboxApprove  Inbox = "approve"  // 4 Ready to approve
	InboxReport   Inbox = "report"   // 5 Ready to mark reported
	InboxThreads  Inbox = "threads"  // 6 Open threads on my findings
	InboxBoard    Inbox = "board"    // 7 New on team board
)

// QueueOrder is the one order the inbox shows its queues in.
var QueueOrder = []Inbox{InboxNotes, InboxReturned, InboxReview, InboxApprove, InboxReport, InboxThreads, InboxBoard}

var roleQueues = map[string][]Inbox{
	"pentester": {InboxNotes, InboxReturned, InboxThreads, InboxBoard},
	"reviewer":  {InboxNotes, InboxReview, InboxThreads, InboxBoard},
	"director":  {InboxNotes, InboxApprove, InboxReport, InboxBoard},
}

// Queues are the inbox queues of u's role, in QueueOrder; everyone has
// Notifications and New on team board (the standard workflow:
// Flow{}.Queues).
func Queues(u config.User) []Inbox { return Flow{}.Queues(u) }

// Pending classifies whether a finding needs u's attention, and in which
// finding queue (threads and the board are classified elsewhere). An own
// draft that was not returned waits for no one: the findings list has it.
func Pending(u config.User, m finding.Meta) Inbox {
	switch {
	// a director who also reviews it approves it once someone else signed off
	case m.Status == "verification" && manager(u) && reviewedByOther(u, m):
		return InboxApprove
	case m.Status == "verification" && reviewer(u, m) && !slices.Contains(m.ClearedBy, u.Username):
		return InboxReview
	case m.Status == "complete" && manager(u):
		return InboxReport
	case m.Status == "draft" && m.Author == u.Username && m.Returned != nil:
		return InboxReturned
	}
	return InboxNone
}
