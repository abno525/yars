package store

import (
	"strconv"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/workflow"
)

const todoRule = "- id: todo\n  target: sections\n  regex_forbid: 'TODO'\n  message: no TODO left\n"

// D18: dismissing one check result affects that row only: the same wording
// in another section still counts (gate, open checks, stored counts) and
// keeps its thread open.
func TestDismissOneRowOnly(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, todoRule)
	s.UpdateSection(eng, fd, "Description", "a TODO here", "", alice)
	s.UpdateSection(eng, fd, "Remediation", "a TODO there", "", alice)
	checked(t, s, fd)
	if err := s.DismissWhy(eng, fd, "todo", "section:Description", "TODO", "fine here", uBob); err != nil {
		t.Fatal(err)
	}
	open, err := s.OpenChecks(eng, fd)
	if err != nil || len(open) != 1 || open[0].Target != "section:Remediation" {
		t.Fatalf("open checks %+v %v", open, err)
	}
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); !denied(err) || !strings.Contains(err.Error(), "no TODO left") {
		t.Fatalf("submit with the other row open: %v", err)
	}
	th := checkThreads(t, s, fd)
	if !th["Description"].Resolved || th["Remediation"].Resolved {
		t.Fatalf("threads: Description resolved %v, Remediation resolved %v", th["Description"].Resolved, th["Remediation"].Resolved)
	}
	ref := load(t, s, fd)
	runs, err := s.DB().LatestRuns([][2]string{{eng, ref.F.Meta.ID}})
	if err != nil || runs[eng+"/"+ref.F.Meta.ID].Errors != 1 {
		t.Fatalf("stored counts %+v %v", runs, err)
	}
	// a new run keeps the one dismissal and the other thread
	checked(t, s, fd)
	if th := checkThreads(t, s, fd); !th["Description"].Resolved || th["Remediation"].Resolved {
		t.Fatal("threads after a second run")
	}
	// restoring it restores that row only
	if err := s.Undismiss(eng, fd, "todo", "section:Description", "TODO", uBob); err != nil {
		t.Fatal(err)
	}
	if open, _ := s.OpenChecks(eng, fd); len(open) != 2 {
		t.Fatalf("after undismiss %+v", open)
	}
}

// The same wording found twice in one place is one result row: counts,
// open checks and a dismissal agree (D18).
func TestSameQuoteTwiceOneRow(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: tick\n  target: sections\n  regex_forbid: '`'\n  message: no backticks\n")
	s.UpdateSection(eng, fd, "Description", "see `/api/items` here", "", alice)
	ref := load(t, s, fd)
	st := checked(t, s, fd)
	n := 0
	for _, r := range st.Results {
		if r.Rule == "tick" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("results %+v", st.Results)
	}
	if runs, _ := s.DB().LatestRuns([][2]string{{eng, ref.F.Meta.ID}}); runs[eng+"/"+ref.F.Meta.ID].Errors != 1 {
		t.Fatalf("stored counts %+v", runs)
	}
	if open, err := s.OpenChecks(eng, fd); err != nil || len(open) != 1 {
		t.Fatalf("open checks %+v %v", open, err)
	}
}

// A rule's step counts its result rows: a quote found twice in one place
// is one hit, as the checks table lists it.
func TestStepCountsRows(t *testing.T) {
	v := rules.Violation{Rule: "tick", Level: "error", Target: "details:Location", Quote: "`"}
	w := v
	w.Quote = "x"
	if x := stepOutcome(1, rules.Rule{ID: "tick"}, []rules.Violation{v, v, w}); x.Hits != 2 {
		t.Fatalf("hits %d", x.Hits)
	}
}

// A rule with more results than it shows has a last row that counts the
// rest. The rule's step counts them too, and a dismissal of that row covers
// its count only: one more hidden result is a new row.
func TestRowThatCountsTheRest(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: tee\n  target: sections\n  regex_forbid: 'T\\d+'\n  message: no T numbers\n")
	words := func(n int) string {
		var b strings.Builder
		for i := range n {
			b.WriteString("T" + strconv.Itoa(i) + " ")
		}
		return b.String()
	}
	more := func(vs []rules.Violation) (rows int, last rules.Violation) {
		for _, v := range vs {
			if v.Rule != "tee" {
				continue
			}
			if _, ok := rules.More(v); ok {
				last = v
			} else {
				rows++
			}
		}
		return rows, last
	}
	s.UpdateSection(eng, fd, "Description", words(25), "", alice)
	st := checked(t, s, fd)
	if x := stepOf(t, st, "tee"); x.State != db.StepHits || x.Hits != 25 {
		t.Fatalf("step %+v", x)
	}
	open, err := s.OpenChecks(eng, fd)
	rows, last := more(open)
	if err != nil || rows != rules.MaxPerRule || last.Message != "and 5 more" || last.Level != "error" {
		t.Fatalf("open checks: %d rows, last %+v, %v", rows, last, err)
	}
	if err := s.DismissWhy(eng, fd, "tee", last.Target, "", "seen them all", uBob); err != nil {
		t.Fatal(err)
	}
	open, _ = s.OpenChecks(eng, fd)
	if rows, last := more(open); rows != rules.MaxPerRule || last.Message != "" {
		t.Fatalf("after the dismissal: %d rows, last %+v", rows, last)
	}
	s.UpdateSection(eng, fd, "Description", words(26), "", alice)
	open, _ = s.OpenChecks(eng, fd)
	if _, last := more(open); last.Message != "and 6 more" {
		t.Fatalf("one more hidden result: last %+v", last)
	}
	// the row is not one Fix with AI works on: it quotes nothing
	if n := FixCount(checked(t, s, fd)); n != rules.MaxPerRule {
		t.Fatalf("fixable %d", n)
	}
}

// A dismissal stored before D18 (keyed by rule and quote only) still
// dismisses the violation everywhere, as it did when it was made.
func TestLegacyDismissalStillCounts(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, todoRule)
	s.UpdateSection(eng, fd, "Description", "a TODO here", "", alice)
	ref := load(t, s, fd)
	s.DB().TxFor(eng, func(tx *db.Tx) error {
		return tx.Dismiss(db.Dismissal{Eng: eng, Fid: ref.F.Meta.ID, Rule: "todo", QuoteHash: BodyHash("TODO"), Level: "error", By: "bob"})
	})
	if open, err := s.OpenChecks(eng, fd); err != nil || len(open) != 0 {
		t.Fatalf("legacy dismissal ignored: %+v %v", open, err)
	}
	checked(t, s, fd)
	ref = load(t, s, fd)
	if runs, _ := s.DB().LatestRuns([][2]string{{eng, ref.F.Meta.ID}}); runs[eng+"/"+ref.F.Meta.ID].Errors != 0 {
		t.Fatalf("stored counts %+v", runs)
	}
}

// D18: the first run after the upgrade turns an old quote-only dismissal
// into a dismissal of each place the quote is in then, and the old one
// ends: the same wording added to another section later counts.
func TestLegacyDismissalEndsAtFirstRun(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, todoRule)
	s.UpdateSection(eng, fd, "Description", "a TODO here", "", alice)
	ref := load(t, s, fd)
	s.DB().TxFor(eng, func(tx *db.Tx) error {
		return tx.Dismiss(db.Dismissal{Eng: eng, Fid: ref.F.Meta.ID, Rule: "todo", QuoteHash: db.LegacyHash("TODO"), Level: "error", By: "bob"})
	})
	checked(t, s, fd)
	ds, _ := s.Dismissals(eng, ref.F.Meta.ID)
	if _, ok := ds[db.DismissKey("todo", db.LegacyHash("TODO"))]; ok {
		t.Fatalf("old dismissal kept: %+v", ds)
	}
	if _, ok := ds[db.DismissKey("todo", ViolationHash("section:Description", "TODO"))]; !ok {
		t.Fatalf("no dismissal of the place: %+v", ds)
	}
	s.UpdateSection(eng, fd, "Remediation", "a TODO there", "", alice)
	checked(t, s, fd)
	open, err := s.OpenChecks(eng, fd)
	if err != nil || len(open) != 1 || open[0].Target != "section:Remediation" {
		t.Fatalf("open checks %+v %v", open, err)
	}
	if th := checkThreads(t, s, fd); th["Remediation"] == nil || th["Remediation"].Resolved {
		t.Fatalf("no open comment on the new place: %+v", th)
	}
}
