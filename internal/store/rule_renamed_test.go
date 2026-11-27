package store

import (
	"strings"
	"testing"
)

// A rule renamed on Admin › Rules takes its stored results with it, as it
// takes its dismissals: a result dismissed under the old ID stays dismissed
// without a new check (open checks, the strip, the stored counts), and the
// next check keeps the result's thread.
func TestRuleRenamedMovesStoredResults(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, todoRule)
	s.UpdateSection(eng, fd, "Description", "a TODO here", "", alice)
	s.UpdateSection(eng, fd, "Remediation", "a TODO there", "", alice)
	checked(t, s, fd)
	if err := s.DismissWhy(eng, fd, "todo", "section:Description", "TODO", "fine here", uBob); err != nil {
		t.Fatal(err)
	}
	before := checkThreads(t, s, fd)
	fid := load(t, s, fd).F.Meta.ID

	withRules(t, s, dir, strings.Replace(todoRule, "id: todo", "id: todo-left", 1))
	if err := s.RuleRenamed("todo", "todo-left", "dora"); err != nil {
		t.Fatal(err)
	}
	open, err := s.OpenChecks(eng, fd)
	if err != nil || len(open) != 1 || open[0].Target != "section:Remediation" || open[0].Rule != "todo-left" {
		t.Fatalf("open checks %+v %v", open, err)
	}
	items, err := s.CheckItems(eng, fd)
	if err != nil || len(items) != 2 {
		t.Fatalf("check items %+v %v", items, err)
	}
	for _, v := range items {
		if v.Rule != "todo-left" {
			t.Fatalf("check items %+v", items)
		}
	}
	if runs, err := s.DB().LatestRuns([][2]string{{eng, fid}}); err != nil || runs[eng+"/"+fid].Errors != 1 {
		t.Fatalf("stored counts %+v %v", runs, err)
	}
	st, err := s.CheckStatus(eng, fd)
	if err != nil || len(st.Results) != 2 {
		t.Fatalf("status %+v %v", st, err)
	}
	for _, r := range st.Results {
		if r.Rule != "todo-left" {
			t.Fatalf("results %+v", st.Results)
		}
	}
	if len(st.Steps) != 1 || st.Steps[0].Rule != "todo-left" {
		t.Fatalf("steps %+v", st.Steps)
	}

	// the next check finds the same rows: their threads stay
	checked(t, s, fd)
	after := checkThreads(t, s, fd)
	if len(after) != 2 || after["Remediation"].Root.ID != before["Remediation"].Root.ID || after["Remediation"].Resolved ||
		after["Description"].Root.ID != before["Description"].Root.ID || !after["Description"].Resolved {
		t.Fatalf("threads after the next check: %+v", after)
	}
	if open, err := s.OpenChecks(eng, fd); err != nil || len(open) != 1 {
		t.Fatalf("open checks after the next check %+v %v", open, err)
	}
}
