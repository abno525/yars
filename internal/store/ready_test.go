package store

import (
	"context"
	"strings"
	"testing"

	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/rules"
	"yars/internal/workflow"
)

// D25: a finding reaches a director only clean. An open warning (not only an
// error) blocks Sign off and Approve until a reviewer dismisses it; Submit
// is still blocked by errors only.
func TestOpenWarningBlocksSignOffAndApprove(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: soft\n  target: title\n  regex_forbid: 'SQL'\n  level: warning\n  message: say what SQL means\n")
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatalf("a warning blocked submit: %v", err)
	}
	err := s.Transition(eng, fd, workflow.Clear, "", uBob)
	if !denied(err) || !strings.Contains(err.Error(), "say what SQL means") {
		t.Fatalf("sign off with an open warning: %v", err)
	}
	if err := s.Dismiss(eng, fd, "soft", "SQL", uBob); err != nil {
		t.Fatal(err)
	}
	checkNow(t, s, fd) // Require Check (on by default)
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatalf("sign off after the dismissal: %v", err)
	}
	// the warning counts again: the director cannot approve
	if err := s.Undismiss(eng, fd, "soft", "", "SQL", uBob); err != nil {
		t.Fatal(err)
	}
	err = s.Transition(eng, fd, workflow.Approve, "", uDora)
	if !denied(err) || !strings.Contains(err.Error(), "say what SQL means") {
		t.Fatalf("approve with an open warning: %v", err)
	}
	if load(t, s, fd).F.Meta.Status != "verification" {
		t.Fatal("approved")
	}
	if err := s.Dismiss(eng, fd, "soft", "SQL", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatalf("approve once clean: %v", err)
	}
}

// slowLinter finds a warning only when slow rules run (an AI rule), and
// counts those runs.
type slowLinter struct{ slow *int }

func (l slowLinter) Lint(_ context.Context, _ *finding.Finding, k rules.Kind) []rules.Violation {
	if k == rules.Fast {
		return nil
	}
	*l.slow++
	return []rules.Violation{{Rule: "ai-x", Level: "warning", Message: "AI says vague", Target: "section:Impact", Quote: "q"}}
}

// Sign off never runs script or AI rules inline: it counts the fast rules
// now and the stored results of the latest run on this content. A stored
// warning blocks it until dismissed; a run on older content does not count.
func TestSignOffUsesStoredRun(t *testing.T) {
	s, _, fd := ready(t)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	var slow int
	s.Linter = slowLinter{&slow}
	ref := load(t, s, fd)
	run := func(hash string) {
		id, err := s.DB().StartRun(eng, ref.F.Meta.ID, hash, "bob", "")
		if err != nil {
			t.Fatal(err)
		}
		s.DB().TxFor(eng, func(tx *db.Tx) error {
			return tx.FinishRun(id, db.RunDone, "", []db.CheckResult{{Rule: "ai-x", Level: "warning", Message: "AI says vague", Target: "section:Impact", Quote: "q", QuoteHash: "qh"}})
		})
	}
	run("older content")
	if open, err := s.OpenChecks(eng, fd); err != nil || len(open) != 0 {
		t.Fatalf("a stale run counts: %v %v", open, err)
	}
	run(ref.Hash)
	err := s.Transition(eng, fd, workflow.Clear, "", uBob)
	if !denied(err) || !strings.Contains(err.Error(), "AI says vague (warning)") {
		t.Fatalf("sign off with a stored warning: %v", err)
	}
	s.DB().TxFor(eng, func(tx *db.Tx) error {
		return tx.Dismiss(db.Dismissal{Eng: eng, Fid: ref.F.Meta.ID, Rule: "ai-x", QuoteHash: "qh", Level: "warning", By: "bob"})
	})
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatalf("sign off once dismissed: %v", err)
	}
	if slow != 0 {
		t.Fatalf("sign off ran the slow rules %d times", slow)
	}
	// Approve runs every rule once more (TestApproveRunsSlowRules); its
	// warning is the dismissed one
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatalf("approve: %v", err)
	}
}

// A check run in progress does not hide the finished run before it: its
// warning still blocks Sign off while the new run goes on.
func TestRunningCheckKeepsFinishedResults(t *testing.T) {
	s, _, fd := ready(t)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	var slow int
	s.Linter = slowLinter{&slow}
	ref := load(t, s, fd)
	id, err := s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	s.DB().TxFor(eng, func(tx *db.Tx) error {
		return tx.FinishRun(id, db.RunDone, "", []db.CheckResult{{Rule: "ai-x", Level: "warning", Message: "AI says vague", Target: "section:Impact", Quote: "q", QuoteHash: "qh"}})
	})
	second, err := s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	s.DB().RunProgress(second, 0, 3)
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); !denied(err) || !strings.Contains(err.Error(), "AI says vague") {
		t.Fatalf("sign off while a new run goes on: %v", err)
	}
	// cut off (a crash after its last rule): no results, so it hides
	// nothing either
	s.DB().RunProgress(second, 3, 3)
	if err := s.DB().FailRun(second, "crashed: boom"); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); !denied(err) || !strings.Contains(err.Error(), "AI says vague") {
		t.Fatalf("sign off after an interrupted run: %v", err)
	}
	// a run where the AI rule failed (provider down) says nothing about its
	// earlier warning; another rule's result of that run counts
	third, _ := s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob", "")
	s.DB().AddSteps([]db.CheckStep{{RunID: third, Pos: 0, Rule: "ai-x", Kind: "ai", State: db.StepFailed}, {RunID: third, Pos: 1, Rule: "re", Kind: "pattern", State: db.StepHits}})
	s.DB().TxFor(eng, func(tx *db.Tx) error {
		return tx.FinishRun(third, db.RunFailed, "AI down", []db.CheckResult{
			{Rule: "ai-x", Level: "warning", Message: "AI not reachable", Target: "ai", QuoteHash: "n"},
			{Rule: "re", Level: "warning", Message: "regex says", Target: "title", Quote: "SQL", QuoteHash: "r"},
		})
	})
	err = s.Transition(eng, fd, workflow.Clear, "", uBob)
	if !denied(err) || !strings.Contains(err.Error(), "AI says vague") || !strings.Contains(err.Error(), "regex says") || strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("sign off after a run where the AI failed: %v", err)
	}
}

// An open error also blocks Sign off (not only Submit and Approve).
func TestOpenErrorBlocksSignOff(t *testing.T) {
	s, dir, fd := ready(t)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	withRules(t, s, dir, "- id: t\n  target: title\n  regex_forbid: 'SQL'\n  message: no SQL in titles\n")
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); !denied(err) || !strings.Contains(err.Error(), "no SQL in titles") {
		t.Fatalf("sign off with an open error: %v", err)
	}
}
