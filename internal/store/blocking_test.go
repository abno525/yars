package store

import (
	"strings"
	"testing"

	"yars/internal/workflow"
)

// BlockingNow words what would refuse an action as Transition does, with
// the fast rules; nothing without rules or for an action that runs none.
func TestBlockingNow(t *testing.T) {
	s, dir, fd := ready(t)
	s.Linter = nil
	if why, err := s.BlockingNow(eng, fd, workflow.Submit, uAlice); err != nil || why != "" {
		t.Fatalf("without rules: %q %v", why, err)
	}
	withRules(t, s, dir, checkRules)
	why, err := s.BlockingNow(eng, fd, workflow.Submit, uAlice)
	if err != nil || !strings.HasPrefix(why, "cannot submit for verification: ") {
		t.Fatalf("with rules: %q %v", why, err)
	}
	if w, _ := s.BlockingNow(eng, fd, workflow.Withdraw, uAlice); w != "" {
		t.Fatalf("withdraw runs no rules: %q", w)
	}
	terr := s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if terr == nil || terr.Error() != why {
		t.Fatalf("Transition said %v, BlockingNow %q", terr, why)
	}
}
