package store

import (
	"context"

	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/rules"
	"yars/internal/workflow"
)

// CheckUser is the author of the chat threads and events check runs write.
const CheckUser = "yars"

// EventCheckFixed is the chat event earlier versions wrote when a run no
// longer found a violation; runs now resolve its thread silently, and the
// event is kept only to show old chats.
const EventCheckFixed = "check_fixed"

// Checker is a Linter that also reports progress over a full run.
type Checker interface {
	Check(ctx context.Context, f *finding.Finding, progress func(done, total int)) []rules.Violation
}

// StepChecker is a Checker that also runs rule by rule: the rules a run
// has, and a run (or one rule alone) telling hooks about each rule.
type StepChecker interface {
	CheckRules() []rules.Rule
	CheckWith(ctx context.Context, f *finding.Finding, h rules.Hooks) []rules.Violation
}

// CheckStatus is a finding's latest check run as seen now.
type CheckStatus struct {
	Ref       FindingRef
	Run       db.CheckRun
	HasRun    bool
	Running   bool // in progress in this server
	Stale     bool // the finding or the rules changed since the run started
	Results   []db.CheckResult
	Steps     []db.CheckStep          // each rule of the run, in order
	Dismissed map[string]db.Dismissal // by db.DismissKey
}

// QuoteHash identifies a violation's quote for dismissals and comments.
func QuoteHash(quote string) string { return BodyHash(quote) }

// ViolationHash identifies a violation of a rule for dismissals and
// comments: where it is and its quote, so that one dismissal covers one
// result row only (db.ViolationHash).
func ViolationHash(target, quote string) string { return db.ViolationHash(target, quote) }

func checkKey(eng, fid string) string { return eng + "/" + fid }

// notice reports a violation about the rules themselves (a broken rule
// file, a rule that could not run, AI not configured): stored with the run
// but never posted as a comment.
func notice(v rules.Violation) bool { return v.Target == "rules" || v.Target == "ai" }

// SignsOff reports whether an action hands a finding on towards a director
// (Sign off, Approve): it needs the finding clean, warnings dismissed too.
func SignsOff(act workflow.Action) bool { return act == workflow.Clear || act == workflow.Approve }
