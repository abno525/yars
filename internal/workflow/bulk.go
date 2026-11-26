package workflow

import (
	"slices"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
)

// BulkOption is one entry of the bulk "Set state" menu: the action, the
// status it leads to, and the menu text (Label · Verb).
type BulkOption struct {
	Action      Action
	To          string
	Label, Verb string
}

func bulkOpt(a Action, label, verb string) BulkOption { return Flow{}.bulkOpt(a, label, verb) }

// bulkOpt is the menu entry of a in this flow (its target status).
func (f Flow) bulkOpt(a Action, label, verb string) BulkOption {
	_, to := f.Target(a)
	return BulkOption{Action: a, To: to, Label: label, Verb: verb}
}

// bulkMenus are the bulk targets of each role, in menu order. A pentester
// acts on own findings only (Check holds them to authorship); a reviewer
// signs off and returns findings they review; a director moves any finding.
var bulkMenus = map[string][]BulkOption{
	"pentester": {bulkOpt(Submit, "Verification", "submit"), bulkOpt(TakeBack, "Draft", "take back"),
		bulkOpt(Report, "Reported", "mark reported"), bulkOpt(Reopen, "Verification", "revert"), bulkOpt(Unreport, "Complete", "revert"),
		bulkOpt(Withdraw, "Withdrawn", "")},
	"reviewer": {bulkOpt(Clear, "Signed off", "sign off"), bulkOpt(Return, "Draft", "return")},
	"director": {bulkOpt(TakeBack, "Draft", "take back"), bulkOpt(Submit, "Verification", "submit"),
		bulkOpt(Approve, "Complete", "approve"), bulkOpt(Report, "Reported", "mark reported"),
		bulkOpt(Reopen, "Verification", "revert"), bulkOpt(Unreport, "Complete", "revert"), bulkOpt(Withdraw, "Withdrawn", "")},
}

// simpleBulk is the bulk Set state menu of the simple workflow, the same for
// every account; no two entries share a label.
var simpleBulk = []BulkOption{
	Flow{Simple: true}.bulkOpt(Complete, "Complete", ""), // the state is the verb: no "Complete · complete"
	Flow{Simple: true}.bulkOpt(Report, "Reported", "mark reported"),
	Flow{Simple: true}.bulkOpt(Reopen, "Draft", "revert"),
	Flow{Simple: true}.bulkOpt(Unreport, "Back to complete", "revert"),
	Flow{Simple: true}.bulkOpt(Withdraw, "Withdrawn", ""),
}

// BulkOptions is u's bulk Set state menu (nil for an unknown role), in the
// standard workflow (Flow{}.BulkOptions).
func BulkOptions(u config.User) []BulkOption { return Flow{}.BulkOptions(u) }

// BulkAllowed reports whether a is on u's bulk menu (standard workflow).
func BulkAllowed(u config.User, a Action) bool { return Flow{}.BulkAllowed(u, a) }

// BulkAssign reports whether u's bulk bar can assign reviewers (standard
// workflow).
func BulkAssign(u config.User) bool { return Flow{}.BulkAssign(u) }

// BulkPick reports whether u may tick m's row on the bulk bar (standard
// workflow: Flow{}.BulkPick).
func BulkPick(u config.User, m finding.Meta) bool { return Flow{}.BulkPick(u, m) }

// BulkCheck reports whether u may apply a to m from the bulk bar (standard
// workflow: Flow{}.BulkCheck).
func BulkCheck(u config.User, m finding.Meta, a Action) error { return Flow{}.BulkCheck(u, m, a) }

// BulkOptions is u's bulk Set state menu in this flow: by role in the
// standard workflow (nil for an unknown role), one menu for everyone in the
// simple one.
func (f Flow) BulkOptions(u config.User) []BulkOption {
	if f.Simple {
		return simpleBulk
	}
	return bulkMenus[u.Role]
}

// BulkAllowed reports whether a is on u's bulk menu.
func (f Flow) BulkAllowed(u config.User, a Action) bool {
	return slices.ContainsFunc(f.BulkOptions(u), func(o BulkOption) bool { return o.Action == a })
}

// BulkAssign reports whether u's bulk bar can assign reviewers: a reviewer
// or a director, in the standard workflow only.
func (f Flow) BulkAssign(u config.User) bool { return !f.Simple && AtLeast(u, "reviewer") }

// BulkPick reports whether u may tick m's row on the bulk bar: in the
// standard workflow a pentester own findings only, a reviewer or director
// any finding; in the simple one anyone any finding. It only shapes the
// page; every posted row is checked again (BulkCheck, store) on the server.
func (f Flow) BulkPick(u config.User, m finding.Meta) bool {
	if f.BulkOptions(u) == nil {
		return false
	}
	return f.Simple || AtLeast(u, "reviewer") || u.Username == m.Author
}

// BulkCheck reports whether u may apply a to m from the bulk bar: a must be
// on u's menu and pass the flow's Check. Below director, the bulk Withdrawn
// entry takes drafts only (the finding page also withdraws an own finding
// in verification).
func (f Flow) BulkCheck(u config.User, m finding.Meta, a Action) error {
	if !f.BulkAllowed(u, a) {
		switch {
		case f.Simple && slices.Contains(Actions, a) && !slices.Contains(SimpleActions, a):
			return notSimple(a)
		case f.Simple:
			return deny("%s is not a bulk action", Label(a))
		}
		return deny("%s is not a bulk action of a %s", Label(a), u.Role)
	}
	if a == Withdraw && !manager(u) && m.Status != "draft" {
		return deny("only drafts can be withdrawn here (finding is %s)", m.Status)
	}
	return f.Check(u, m, a)
}
