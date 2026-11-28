package store

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/workflow"
)

// stuckAI never answers an AI question: the call ends with its context, as
// a provider that hangs, and notes the deadline it used up. A script that is
// handed that same deadline has no time left and fails as the real runner's
// does; any other script runs as the engine's own runner runs it, off the
// test's short timer, so a slow machine changes no answer.
type stuckAI struct {
	rules.SlowRunner
	mu    sync.Mutex
	spent []time.Time
}

func (s *stuckAI) AI(ctx context.Context, r rules.Rule, target, text string) []rules.Violation {
	<-ctx.Done()
	if at, ok := ctx.Deadline(); ok {
		s.mu.Lock()
		s.spent = append(s.spent, at)
		s.mu.Unlock()
	}
	return []rules.Violation{{Rule: r.ID, Level: "warning", Target: "ai", Message: "AI check failed: timeout"}}
}

func (s *stuckAI) Script(ctx context.Context, r rules.Rule, d rules.Doc) []rules.Violation {
	at, ok := ctx.Deadline()
	s.mu.Lock()
	over := ok && slices.ContainsFunc(s.spent, at.Equal)
	s.mu.Unlock()
	if over {
		return []rules.Violation{{Rule: r.ID, Level: r.Level, Target: "rules", Message: "rule failed: timed out", Fail: "timed out"}}
	}
	return s.SlowRunner.Script(context.WithoutCancel(ctx), r, d)
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
	e.Runner, e.Budget = &stuckAI{SlowRunner: e.Runner}, 30*time.Millisecond
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
