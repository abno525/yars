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
)

var Actions = []Action{Submit, Return, Clear, Approve, Reopen, Report}

// Statuses in workflow order.
var Statuses = []string{"draft", "verification", "complete", "reported"}

// Denied explains why an action is not allowed.
type Denied struct{ Reason string }

func (d *Denied) Error() string { return d.Reason }

func deny(format string, a ...any) error { return &Denied{Reason: fmt.Sprintf(format, a...)} }

// Target returns the status an action requires and the status it produces.
func Target(a Action) (from, to string) {
	switch a {
	case Submit:
		return "draft", "verification"
	case Return:
		return "verification", "draft"
	case Clear:
		return "verification", "verification"
	case Approve:
		return "verification", "complete"
	case Reopen:
		return "complete", "verification"
	case Report:
		return "complete", "reported"
	}
	return "", ""
}

func Label(a Action) string {
	return map[Action]string{Submit: "Submit for verification", Return: "Return to draft", Clear: "Clear",
		Approve: "Approve", Reopen: "Reopen", Report: "Mark reported"}[a]
}

// AtLeast reports whether u's role is role or a stronger one. Roles only add
// power, in the order of config.Roles: pentester < reviewer < director < admin.
func AtLeast(u config.User, role string) bool {
	have, want := slices.Index(config.Roles, u.Role), slices.Index(config.Roles, role)
	return have >= 0 && want >= 0 && have >= want
}

func manager(u config.User) bool { return AtLeast(u, "director") }

func reviewer(u config.User, m finding.Meta) bool { return slices.Contains(m.Reviewers, u.Username) }

// Check reports whether u may perform a on a finding with meta m.
func Check(u config.User, m finding.Meta, a Action) error {
	from, _ := Target(a)
	if from == "" {
		return deny("unknown action %q", a)
	}
	if m.Status != from {
		return deny("%s is only possible in %s (finding is %s)", Label(a), from, m.Status)
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
	case Reopen, Report:
		if !manager(u) {
			return deny("only a director can %s", strings.ToLower(Label(a)))
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
	if m.Status == "complete" || m.Status == "reported" {
		return manager(u)
	}
	return true
}

// CanAssign reports whether u may change the reviewer list.
func CanAssign(u config.User, m finding.Meta) bool {
	if m.Status != "draft" && m.Status != "verification" {
		return false
	}
	return u.Username == m.Author || manager(u)
}

// ReviewerCandidate reports whether u may be assigned as a reviewer of m.
func ReviewerCandidate(u config.User, m finding.Meta) bool {
	return AtLeast(u, "reviewer") && u.Username != m.Author
}

type Inbox string

const (
	InboxNone     Inbox = ""
	InboxReview   Inbox = "review"
	InboxApprove  Inbox = "approve"
	InboxReturned Inbox = "returned"
)

// Pending classifies whether a finding needs u's attention.
func Pending(u config.User, m finding.Meta) Inbox {
	switch {
	case m.Status == "verification" && reviewer(u, m) && !slices.Contains(m.ClearedBy, u.Username):
		return InboxReview
	case m.Status == "verification" && manager(u) && reviewedByOther(u, m):
		return InboxApprove
	case m.Status == "draft" && m.Author == u.Username && m.Returned != nil:
		return InboxReturned
	}
	return InboxNone
}
