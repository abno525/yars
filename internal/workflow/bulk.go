package workflow

import (
	"slices"

	"yars/internal/config"
	"yars/internal/finding"
)

// BulkOption is one entry of the bulk "Set state" menu: the action, the
// status it leads to, and the menu text (Label · Verb).
type BulkOption struct {
	Action      Action
	To          string
	Label, Verb string
}

func bulkOpt(a Action, label, verb string) BulkOption {
	_, to := Target(a)
	return BulkOption{Action: a, To: to, Label: label, Verb: verb}
}

// bulkMenus are the bulk targets of each role, in menu order. A pentester
// acts on own findings only (Check holds them to authorship); a reviewer
// signs off and returns findings they review; a director moves any finding.
var bulkMenus = map[string][]BulkOption{
	"pentester": {bulkOpt(Submit, "Verification", "submit"), bulkOpt(TakeBack, "Draft", "take back"),
		bulkOpt(Report, "Reported", "mark reported"), bulkOpt(Withdraw, "Withdrawn", "")},
	"reviewer": {bulkOpt(Clear, "Signed off", "sign off"), bulkOpt(Return, "Draft", "return")},
	"director": {bulkOpt(TakeBack, "Draft", "take back"), bulkOpt(Submit, "Verification", "submit"),
		bulkOpt(Approve, "Complete", "approve"), bulkOpt(Report, "Reported", "mark reported"), bulkOpt(Withdraw, "Withdrawn", "")},
}

// BulkOptions is u's bulk Set state menu (nil for an unknown role).
func BulkOptions(u config.User) []BulkOption { return bulkMenus[u.Role] }

// BulkAllowed reports whether a is on u's bulk menu.
func BulkAllowed(u config.User, a Action) bool {
	return slices.ContainsFunc(BulkOptions(u), func(o BulkOption) bool { return o.Action == a })
}

// BulkAssign reports whether u's bulk bar can assign reviewers.
func BulkAssign(u config.User) bool { return AtLeast(u, "reviewer") }

// BulkPick reports whether u may tick m's row on the bulk bar: a pentester
// own findings only, a reviewer or director any finding. It only shapes the
// page; every posted row is checked again (BulkCheck, store) on the server.
func BulkPick(u config.User, m finding.Meta) bool {
	if BulkOptions(u) == nil {
		return false
	}
	return AtLeast(u, "reviewer") || u.Username == m.Author
}

// BulkCheck reports whether u may apply a to m from the bulk bar: a must be
// on u's menu and pass Check. Below director, the bulk Withdrawn entry takes
// drafts only (the finding page also withdraws an own finding in
// verification).
func BulkCheck(u config.User, m finding.Meta, a Action) error {
	if !BulkAllowed(u, a) {
		return deny("%s is not a bulk action of a %s", Label(a), u.Role)
	}
	if a == Withdraw && !manager(u) && m.Status != "draft" {
		return deny("only drafts can be withdrawn here (finding is %s)", m.Status)
	}
	return Check(u, m, a)
}
