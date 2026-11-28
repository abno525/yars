package rules

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
)

// slowFirst is a runner whose rule "slow" never answers: its call waits for
// its context to end, however long that takes, and notes the deadline it
// used up. Every other call answers at once. It fails, as the real runner's
// does (an AI rule with the notice, a script with "timed out"), exactly when
// its context has a deadline the slow rule used up: the same budget. No call
// reads the clock, so a slow machine changes no answer.
type slowFirst struct {
	mu    sync.Mutex
	calls map[string]int
	spent []time.Time            // the deadlines the slow rule waited out
	ends  map[string][]time.Time // each rule's deadlines, a call each
}

// note counts a call and reports whether its budget is one already used up.
func (s *slowFirst) note(ctx context.Context, id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls, s.ends = map[string]int{}, map[string][]time.Time{}
	}
	s.calls[id]++
	at, ok := ctx.Deadline()
	if !ok {
		return false
	}
	s.ends[id] = append(s.ends[id], at)
	return slices.ContainsFunc(s.spent, at.Equal)
}

func (s *slowFirst) Script(ctx context.Context, r Rule, d Doc) []Violation {
	if s.note(ctx, r.ID) {
		return []Violation{{Rule: r.ID, Level: r.Level, Target: "rules", Message: "rule failed: timed out", Fail: "timed out"}}
	}
	return nil
}

func (s *slowFirst) AI(ctx context.Context, r Rule, target, text string) []Violation {
	over := s.note(ctx, r.ID)
	if r.ID == "slow" {
		<-ctx.Done()
		if at, ok := ctx.Deadline(); ok {
			s.mu.Lock()
			s.spent = append(s.spent, at)
			s.mu.Unlock()
		}
		over = true
	}
	if over {
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
				t.Fatalf("calls %v", st.calls)
			}
			// each slow rule has a deadline of its own, later than the one
			// the rule before it had; the parts of one rule share theirs
			order := []string{"slow", "second", "third", "script"}
			for i, id := range order {
				if len(st.ends[id]) != st.calls[id] {
					t.Fatalf("%s ran without a deadline: %v", id, st.ends[id])
				}
				if i > 0 && !st.ends[id][0].After(st.ends[order[i-1]][0]) {
					t.Errorf("%s has the deadline of %s: one budget for both", id, order[i-1])
				}
			}
			for _, id := range []string{"second", "third"} {
				if !st.ends[id][0].Equal(st.ends[id][1]) {
					t.Errorf("the two parts of %s have a deadline each: %v", id, st.ends[id])
				}
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
