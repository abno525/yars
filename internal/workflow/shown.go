package workflow

import (
	"slices"
	"strings"

	"yars/internal/finding"
)

// SignedOff is a display state, never stored: a finding in verification
// whose every assigned reviewer has signed off. The API, MCP and git keep
// reporting such a finding as verification.
const SignedOff = "signed-off"

// ShownSteps are the steps as the UI draws them: Statuses with signed off
// between verification and complete.
var ShownSteps = []string{"draft", "verification", SignedOff, "complete", "reported"}

// ShownAll are the shown steps plus withdrawn.
var ShownAll = append(slices.Clone(ShownSteps), Withdrawn)

// ShownSteps are the flow's steps as the UI draws them: the standard
// workflow's with signed off (ShownSteps), the simple one's as they are
// (Statuses: no verification, so no signed off).
func (f Flow) ShownSteps() []string {
	if f.Simple {
		return simpleStatuses
	}
	return ShownSteps
}

// ShownAll are the flow's shown steps plus withdrawn (bars, legends and the
// status filters, in this order).
func (f Flow) ShownAll() []string {
	if f.Simple {
		return simpleAll
	}
	return ShownAll
}

// Shown is the state the UI shows for m: its status, or SignedOff.
func Shown(m finding.Meta) string {
	if m.Status != "verification" || len(m.Reviewers) == 0 {
		return m.Status
	}
	for _, r := range m.Reviewers {
		if !slices.Contains(m.ClearedBy, r) {
			return m.Status
		}
	}
	return SignedOff
}

// StatusLabel is the text of a shown state.
func StatusLabel(s string) string {
	if s == SignedOff {
		return "signed off"
	}
	return s
}

// StatusTitle is StatusLabel in sentence case ("Signed off"), for filter
// segments and legends; it works for severities too.
func StatusTitle(s string) string {
	l := StatusLabel(s)
	if l == "" {
		return ""
	}
	return strings.ToUpper(l[:1]) + l[1:]
}
