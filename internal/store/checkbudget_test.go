package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/workflow"
)

// stuckAI runs scripts as the engine's own runner does and never answers an
// AI question: the call ends with its context, as a provider that hangs.
type stuckAI struct{ rules.SlowRunner }

func (stuckAI) AI(ctx context.Context, r rules.Rule, target, text string) []rules.Violation {
	<-ctx.Done()
	return []rules.Violation{{Rule: r.ID, Level: "warning", Target: "ai", Message: "AI check failed: timeout"}}
}

// A check whose AI rule used up its time does not take the script rule
// after it down: the script's step passes, the run is done, and Sign off
// goes through, since an AI rule that could not run holds nothing (pre1
// 7.10).
func TestCheckSlowAIRuleFailsAlone(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: slow\n  level: warning\n  target: sections\n  ai: Be short.\n- id: scr\n  script: check.sh\n")
	if err := os.WriteFile(filepath.Join(dir, ".yars", "rules", "check.sh"), []byte("#!/bin/sh\ncat >/dev/null\necho '[]'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSection(eng, fd, "Description", "Some text for the AI rule.", "", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	e := s.Linter.(*rules.Engine)
	e.Runner, e.Budget = stuckAI{e.Runner}, 30*time.Millisecond
	checkNow(t, s, fd)
	st, err := s.CheckStatus(eng, fd)
	if err != nil {
		t.Fatal(err)
	}
	if st.Run.State != db.RunDone {
		t.Fatalf("the run: %+v", st.Run)
	}
	if x := stepOf(t, st, "slow"); x.State != db.StepFailed {
		t.Fatalf("the AI rule's step: %+v", x)
	}
	if x := stepOf(t, st, "scr"); x.State != db.StepPass {
		t.Fatalf("the script's step: %+v", x)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatalf("sign off after a check whose AI rule ran out of time: %v", err)
	}
}
