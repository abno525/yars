// Package workflow holds the status/role rules shared by the web UI, the
// git pre-receive check and the MCP server.
package workflow

import (
	"fmt"
	"slices"
	"strings"

	"yars/internal/config"
	"yars/internal/cvss"
	"yars/internal/finding"
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
)

var Actions = []Action{Submit, Return, Clear, Approve, Reopen, Report, Withdraw, Revise, TakeBack}

// aliases are other accepted names of actions.
var aliases = map[string]Action{"sign_off": Clear}

// ParseAction reads an action name (case-insensitive, aliases accepted:
// sign_off is clear).
func ParseAction(s string) (Action, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if a, ok := aliases[s]; ok {
		return a, true
	}
	a := Action(s)
	return a, slices.Contains(Actions, a)
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

// NeedsReason reports whether an action requires a reason.
func NeedsReason(a Action) bool { return a == Return || a == Withdraw }

// Denied explains why an action is not allowed.
type Denied struct{ Reason string }

func (d *Denied) Error() string { return d.Reason }

func deny(format string, a ...any) error { return &Denied{Reason: fmt.Sprintf(format, a...)} }

// Target returns the statuses an action is possible in and the status it
// produces.
func Target(a Action) (from []string, to string) {
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
		Approve: "Approve", Reopen: "Reopen", Report: "Mark reported", Withdraw: "Withdraw", Revise: "Restore",
		TakeBack: "Take back"}[a]
}

// AtLeast reports whether u's role is role or a stronger one. Roles only add
// power, in the order of config.Roles: pentester < reviewer < director.
func AtLeast(u config.User, role string) bool {
	have, want := slices.Index(config.Roles, u.Role), slices.Index(config.Roles, role)
	return have >= 0 && want >= 0 && have >= want
}

func manager(u config.User) bool { return AtLeast(u, "director") }

func reviewer(u config.User, m finding.Meta) bool { return slices.Contains(m.Reviewers, u.Username) }

// Check reports whether u may perform a on a finding with meta m.
func Check(u config.User, m finding.Meta, a Action) error {
	from, _ := Target(a)
	if from == nil {
		return deny("unknown action %q", a)
	}
	if !slices.Contains(from, m.Status) {
		return deny("%s is only possible in %s (finding is %s)", Label(a), strings.Join(from, " or "), m.Status)
	}
	switch a {
	case Submit:
		if u.Username != m.Author && !manager(u) {
			return deny("only the author or a director can submit")
		}
	case Return:
		if !reviewer(u, m) && !manager(u) {
			return deny("only an assigned reviewer or a director can return a finding")
		}
	case Clear:
		if u.Username == m.Author {
			return deny("the author cannot clear their own finding")
		}
		if !reviewer(u, m) && !manager(u) {
			return deny("only an assigned reviewer or a director can clear")
		}
		if slices.Contains(m.ClearedBy, u.Username) {
			return deny("you already cleared this finding")
		}
	case Approve:
		if !manager(u) {
			return deny("only a director can approve")
		}
		if !reviewedByOther(u, m) {
			return deny("at least one assigned reviewer other than you must clear the finding first")
		}
	case Reopen:
		if !manager(u) {
			return deny("only a director can %s", strings.ToLower(Label(a)))
		}
	case Report:
		if u.Username != m.Author && !manager(u) {
			return deny("only the author or a director can mark a finding reported")
		}
	case TakeBack:
		if u.Username != m.Author && !manager(u) {
			return deny("only the author or a director can take a finding back")
		}
	case Withdraw:
		switch {
		case manager(u):
		case u.Username != m.Author:
			return deny("only the author or a director can withdraw a finding")
		case m.Status != "draft" && m.Status != "verification":
			return deny("only a director can withdraw a %s finding", m.Status)
		}
	case Revise:
		if u.Username != m.Author && !manager(u) {
			return deny("only the author or a director can restore a withdrawn finding")
		}
	}
	return nil
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

// Gated reports whether an action must also pass Gate (content completeness).
func Gated(a Action) bool { return a == Submit || a == Approve }

// CheckWithGate is Check plus, for submit and approve, the content Gate.
func CheckWithGate(u config.User, m finding.Meta, a Action, cfg config.Config) error {
	if err := Check(u, m, a); err != nil {
		return err
	}
	if Gated(a) {
		if p := Gate(m, cfg); len(p) > 0 {
			return deny("cannot %s: %s", strings.ToLower(Label(a)), strings.Join(p, "; "))
		}
	}
	return nil
}

// Gate lists what blocks a draft from being submitted or approved (empty = ready).
func Gate(m finding.Meta, cfg config.Config) []string {
	var p []string
	if len(m.Reviewers) == 0 {
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
	InboxReturned Inbox = "returned" // 1 Returned to me
	InboxReview   Inbox = "review"   // 2 Awaiting my review
	InboxApprove  Inbox = "approve"  // 3 Ready to approve
	InboxReport   Inbox = "report"   // 4 Ready to mark reported
	InboxThreads  Inbox = "threads"  // 5 Open threads on my findings
	InboxBoard    Inbox = "board"    // 6 New on team board
	InboxDraft    Inbox = "drafts"   // 7 My drafts
)

// QueueOrder is the one order the inbox shows its queues in.
var QueueOrder = []Inbox{InboxReturned, InboxReview, InboxApprove, InboxReport, InboxThreads, InboxBoard, InboxDraft}

var roleQueues = map[string][]Inbox{
	"pentester": {InboxReturned, InboxThreads, InboxBoard, InboxDraft},
	"reviewer":  {InboxReview, InboxThreads, InboxBoard},
	"director":  {InboxApprove, InboxReport, InboxBoard},
}

// Queues are the inbox queues of u's role, in QueueOrder; everyone has New
// on team board.
func Queues(u config.User) []Inbox {
	if q, ok := roleQueues[u.Role]; ok {
		return q
	}
	return []Inbox{InboxBoard}
}

// Pending classifies whether a finding needs u's attention, and in which
// finding queue (threads and the board are classified elsewhere).
func Pending(u config.User, m finding.Meta) Inbox {
	switch {
	case m.Status == "verification" && reviewer(u, m) && !slices.Contains(m.ClearedBy, u.Username):
		return InboxReview
	case m.Status == "verification" && manager(u) && reviewedByOther(u, m):
		return InboxApprove
	case m.Status == "complete" && manager(u):
		return InboxReport
	case m.Status == "draft" && m.Author == u.Username && m.Returned != nil:
		return InboxReturned
	case m.Status == "draft" && m.Author == u.Username:
		return InboxDraft
	}
	return InboxNone
}
