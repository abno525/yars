package rules

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
)

// slowFirst is a runner whose rule "slow" never answers: its calls wait for
// their context to end. Every call on a context that is over fails as the
// real runner's does: an AI rule with the notice, a script with "timed out".
type slowFirst struct {
	mu    sync.Mutex
	calls map[string]int
}

func (s *slowFirst) note(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[id]++
}

func (s *slowFirst) Script(ctx context.Context, r Rule, d Doc) []Violation {
	s.note(r.ID)
	if ctx.Err() != nil {
		return []Violation{{Rule: r.ID, Level: r.Level, Target: "rules", Message: "rule failed: timed out", Fail: "timed out"}}
	}
	return nil
}

func (s *slowFirst) AI(ctx context.Context, r Rule, target, text string) []Violation {
	s.note(r.ID)
	if r.ID == "slow" {
		<-ctx.Done()
	}
	if ctx.Err() != nil {
		return []Violation{{Rule: r.ID, Level: "warning", Target: "ai", Message: "AI check failed: timeout"}}
	}
	return nil
}

const budgetRules = "- id: slow\n  target: sections\n  ai: Be short.\n" +
	"- id: second\n  target: sections\n  ai: Be clear.\n" +
	"- id: third\n  target: sections\n  ai: Be kind.\n" +
	"- id: script\n  script: check.sh\n" +
	"- id: fast\n  target: title\n  regex_forbid: 'zebra'\n"

func budgetFinding() *finding.Finding {
	return &finding.Finding{Meta: finding.Meta{ID: "F-001", Title: "A zebra"},
		Sections: []finding.Section{{Name: "Description", Body: "One."}, {Name: "Impact", Body: "Two."}}}
}

// A check run gives each script and AI rule the budget for itself: a rule
// that uses all of it fails alone, and the rules after it run. Before, the
// run had one budget, so every rule after a slow AI rule failed, a script
// among them, which failed the run (pre1 7.10).
func TestCheckBudgetIsPerRule(t *testing.T) {
	dir := writeRules(t, map[string]string{"r.yaml": budgetRules})
	for _, how := range []string{"CheckWith", "Check"} {
		t.Run(how, func(t *testing.T) {
			e := NewEngine(dir, config.Default())
			st := &slowFirst{}
			e.Runner, e.Budget = st, 30*time.Millisecond
			var vs []Violation
			if how == "CheckWith" {
				vs = e.CheckWith(context.Background(), budgetFinding(), Hooks{})
			} else {
				vs = e.Check(context.Background(), budgetFinding(), nil)
			}
			by := map[string][]Violation{}
			for _, v := range vs {
				by[v.Rule] = append(by[v.Rule], v)
			}
			if len(by["slow"]) != 1 || by["slow"][0].Target != "ai" {
				t.Fatalf("the slow rule: %+v", by["slow"])
			}
			for _, id := range []string{"second", "third", "script"} {
				if len(by[id]) != 0 {
					t.Errorf("%s did not run on its own budget: %+v", id, by[id])
				}
			}
			if len(by["fast"]) != 1 {
				t.Errorf("the pattern rule: %+v", by["fast"])
			}
			// the slow rule stops at its first part; the others ask both
			if st.calls["slow"] != 1 || st.calls["second"] != 2 || st.calls["third"] != 2 || st.calls["script"] != 1 {
				t.Errorf("calls %v", st.calls)
			}
		})
	}
}

// The paths that answer inside a request keep one budget for the whole run
// (the write deadline of the request is set from it): after the slow rule
// the rest fail.
func TestLintBudgetIsForTheRun(t *testing.T) {
	dir := writeRules(t, map[string]string{"r.yaml": budgetRules})
	e := NewEngine(dir, config.Default())
	e.Runner, e.Budget = &slowFirst{}, 30*time.Millisecond
	failed := func(vs []Violation) map[string]bool {
		out := map[string]bool{}
		for _, v := range vs {
			if v.Target == "ai" || v.Fail != "" {
				out[v.Rule] = true
			}
		}
		return out
	}
	if f := failed(e.Lint(context.Background(), budgetFinding(), All)); !f["slow"] || !f["second"] || !f["third"] || !f["script"] {
		t.Fatalf("Lint: failed %v", f)
	}
	r, ok := e.Rule("script")
	if !ok {
		t.Fatal("no rule script")
	}
	// one rule on the bench: the same single budget
	slow, _ := e.Rule("slow")
	if f := failed(e.RunRule(context.Background(), slow, DocOf(budgetFinding()))); !f["slow"] {
		t.Fatalf("RunRule: %v", f)
	}
	if f := failed(e.RunRule(context.Background(), r, DocOf(budgetFinding()))); len(f) != 0 {
		t.Fatalf("RunRule of the script: %v", f)
	}
}
