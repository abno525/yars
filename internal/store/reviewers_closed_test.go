package store

import (
	"errors"
	"strings"
	"testing"

	"yars/internal/workflow"
)

// A director who adds reviewers to a finding that is no longer open is told
// the finding is closed, not that a director may not assign reviewers.
func TestAddReviewersClosedSaysWhy(t *testing.T) {
	s, _, fd := ready(t) // alice's, bob reviews
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	for name, err := range map[string]error{
		"add": s.AddReviewers(eng, fd, []string{"carol"}, uDora),
		"set": s.SetReviewers(eng, fd, []string{"bob", "carol"}, uDora),
	} {
		var d *workflow.Denied
		if !errors.As(err, &d) {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(d.Reason, "director can") || !strings.Contains(d.Reason, "complete") {
			t.Fatalf("%s: reason %q", name, d.Reason)
		}
	}
}
