package workflow

import (
	"slices"
	"strings"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
)

// Complete takes a draft straight to complete: the simple workflow's one
// step forward, gated as Approve is (without the reviewer requirement). The
// standard workflow does not have it.
const Complete Action = "complete"

// SimpleActions are the actions of the simple workflow, in the order the
// finding page and the API list them.
var SimpleActions = []Action{Complete, Reopen, Report, Unreport, Withdraw, Revise}

var (
	simpleStatuses = []string{"draft", "complete", "reported"}
	simpleAll      = []string{"draft", "complete", "reported", Withdrawn}
	simpleQueues   = []Inbox{InboxNotes, InboxReport, InboxThreads, InboxBoard}
)

// Flow is a data folder's workflow, set by yars init and fixed after it. The
// zero value is the standard workflow (draft → verification → complete →
// reported, with roles, reviewers and sign-off); Simple is draft → complete
// → reported with neither. It holds no state of its own: the package-level
// functions and values are the standard flow's.
type Flow struct{ Simple bool }

// FlowOf is the workflow config.yaml sets up.
func FlowOf(c config.Config) Flow { return Flow{Simple: c.Simple()} }

// Name is the workflow's name as config.yaml writes it: "standard" or
// "simple".
func (f Flow) Name() string {
	if f.Simple {
		return config.WorkflowSimple
	}
	return config.WorkflowStandard
}

// Actions are the flow's actions in order (the standard: Actions).
func (f Flow) Actions() []Action {
	if f.Simple {
		return SimpleActions
	}
	return Actions
}

// Statuses are the flow's steps in order (the standard: Statuses); the
// simple workflow has no verification.
func (f Flow) Statuses() []string {
	if f.Simple {
		return simpleStatuses
	}
	return Statuses
}

// AllStatuses are the flow's steps plus withdrawn.
func (f Flow) AllStatuses() []string {
	if f.Simple {
		return simpleAll
	}
	return AllStatuses
}

// HasReviewers reports whether the flow has reviewers (assigning them, sign
// offs): the standard one only.
func (f Flow) HasReviewers() bool { return !f.Simple }

// Target returns the statuses an action is possible in and the status it
// produces; an action the flow does not have gives nil.
func (f Flow) Target(a Action) (from []string, to string) {
	if !f.Simple {
		return standardTarget(a)
	}
	switch a {
	case Complete:
		return []string{"draft"}, "complete"
	case Reopen:
		return []string{"complete"}, "draft"
	case Report:
		return []string{"complete"}, "reported"
	case Unreport:
		return []string{"reported"}, "complete"
	case Withdraw:
		return []string{"draft", "complete", "reported"}, Withdrawn
	case Revise:
		return []string{Withdrawn}, "draft"
	}
	return nil, ""
}

// RevertName is how a refusal names a: both reverts are labelled Revert, so
// each says where it goes ("Revert to verification", or "Revert to draft"
// in the simple workflow; "Revert to complete"); any other action is its
// Label.
func (f Flow) RevertName(a Action) string {
	switch a {
	case Reopen:
		if f.Simple {
			return "Revert to draft"
		}
		return "Revert to verification"
	case Unreport:
		return "Revert to complete"
	}
	return Label(a)
}

// notSimple refuses a standard action in the simple workflow.
func notSimple(a Action) error {
	return deny("%s is not part of the simple workflow (draft → complete → reported)", Label(a))
}

// CanReport reports whether u may report a finding with meta m, whatever its
// status: mark it reported, or send it to a destination (which may mark it,
// and sends a reported one again). The finding's author and a director may;
// in the simple workflow every account is a director.
func CanReport(u config.User, m finding.Meta) bool {
	return u.Username == m.Author || manager(u)
}

// Check reports whether u may perform a on a finding with meta m in this
// flow. An action the flow does not have is refused: a standard one in the
// simple workflow says so.
func (f Flow) Check(u config.User, m finding.Meta, a Action) error {
	from, _ := f.Target(a)
	if from == nil {
		if f.Simple && slices.Contains(Actions, a) {
			return notSimple(a)
		}
		return deny("unknown action %q", a)
	}
	if !slices.Contains(from, m.Status) {
		return deny("%s is only possible in %s (finding is %s)", f.RevertName(a), strings.Join(from, " or "), m.Status)
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
		// a director signs off their own finding too (Q25); Approve still
		// needs a sign-off by an assigned reviewer other than the approver
		if u.Username == m.Author && !manager(u) {
			return deny("only a director can sign off their own finding")
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
	case Complete:
		// every account of the simple workflow is a director: anyone
		if u.Username != m.Author && !manager(u) {
			return deny("only the author or a director can complete a finding")
		}
	case Reopen, Unreport:
		// a director can do everything; the author can always move their
		// finding backwards (the user's answer of 2026-11-11)
		if u.Username != m.Author && !manager(u) {
			return deny("only the author or a director can revert a finding")
		}
	case Report:
		if !CanReport(u, m) {
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

// Queues are u's inbox queues in QueueOrder. The standard flow gives each
// role its own set (everyone has Notifications and New on team board); the
// simple one gives every account Notifications, Ready to mark reported,
// Open threads on my findings and New on team board.
func (f Flow) Queues(u config.User) []Inbox {
	if f.Simple {
		return simpleQueues
	}
	if q, ok := roleQueues[u.Role]; ok {
		return q
	}
	return []Inbox{InboxNotes, InboxBoard}
}
