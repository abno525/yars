package store

import (
	"strings"
	"testing"

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
