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
		id, err := s.DB().StartRun(eng, ref.F.Meta.ID, hash, "bob")
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
