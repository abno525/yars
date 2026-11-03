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

func manager(u config.User) bool { return u.Role == "director" || u.Role == "admin" }

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
			return deny("only an assigned reviewer can clear")
		}
		if slices.Contains(m.ClearedBy, u.Username) {
			return deny("you already cleared this finding")
		}
	case Approve:
		if !manager(u) {
			return deny("only a director can approve")
		}
		if len(m.ClearedBy) == 0 {
			return deny("at least one reviewer must clear the finding first")
		}
	case Reopen, Report:
		if !manager(u) {
			return deny("only a director can %s", strings.ToLower(Label(a)))
		}
	}
	return nil
}

// Gate lists what blocks a draft from being submitted (empty = ready).
func Gate(m finding.Meta, cfg config.Config) []string {
	var p []string
	if len(m.Reviewers) == 0 {
		p = append(p, "assign at least one reviewer")
	}
	if strings.TrimSpace(m.Title) == "" {
		p = append(p, "the title is empty")
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
	return (u.Role == "reviewer" || u.Role == "director") && u.Username != m.Author
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
	case m.Status == "verification" && manager(u) && len(m.ClearedBy) > 0:
		return InboxApprove
	case m.Status == "draft" && m.Author == u.Username && m.Returned != nil:
		return InboxReturned
	}
	return InboxNone
}
