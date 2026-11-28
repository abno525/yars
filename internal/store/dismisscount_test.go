package store

import (
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/workflow"
)

// A dismissal covers the matches its row stood for when it was made: the
// same wording added to that place later opens the row again, for the open
// checks, Submit and the stored counts alike. Fewer matches stay dismissed
// (pre1 7.9).
func TestDismissalCoversItsCount(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, todoRule)
	fid := load(t, s, fd).F.Meta.ID
	key := db.DismissKey("todo", ViolationHash("section:Description", "TODO"))
	covers := func() int {
		t.Helper()
		ds, err := s.Dismissals(eng, fid)
		if err != nil {
			t.Fatal(err)
		}
		d, ok := ds[key]
		if !ok {
			t.Fatalf("no dismissal: %+v", ds)
		}
		return d.Covers
	}
	open := func() int {
		t.Helper()
		vs, err := s.OpenChecks(eng, fd)
		if err != nil {
			t.Fatal(err)
		}
		return len(vs)
	}
	stored := func() int {
		t.Helper()
		runs, err := s.DB().LatestRuns([][2]string{{eng, fid}})
		if err != nil {
			t.Fatal(err)
		}
		return runs[eng+"/"+fid].Errors
	}
	s.UpdateSection(eng, fd, "Description", "a TODO here and a TODO there", "", alice)
	checked(t, s, fd)
	if open() != 1 || stored() != 1 {
		t.Fatalf("two matches are one row: open %d, stored %d", open(), stored())
	}
	if err := s.DismissWhy(eng, fd, "todo", "section:Description", "TODO", "fine here", uBob); err != nil {
		t.Fatal(err)
	}
	if n := covers(); n != 2 {
		t.Fatalf("the dismissal covers %d, want 2", n)
	}
	if open() != 0 || stored() != 0 {
		t.Fatalf("dismissed: open %d, stored %d", open(), stored())
	}
	// a third match in the same place: the row is open again
	s.UpdateSection(eng, fd, "Description", "a TODO here and a TODO there and one more TODO", "", alice)
	if open() != 1 {
		t.Fatalf("a third match: open %d", open())
	}
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); !denied(err) || !strings.Contains(err.Error(), "no TODO left") {
		t.Fatalf("submit with a match the dismissal did not cover: %v", err)
	}
	st := checked(t, s, fd)
	if stored() != 1 || open() != 1 {
		t.Fatalf("after a check: stored %d, open %d", stored(), open())
	}
	if n := FixCount(st); n != 1 {
		t.Fatalf("the open row is not one to fix: %d", n)
	}
	// one match less: covered again
	s.UpdateSection(eng, fd, "Description", "a TODO here and a TODO there", "", alice)
	checked(t, s, fd)
	if open() != 0 || stored() != 0 {
		t.Fatalf("back to two: open %d, stored %d", open(), stored())
	}
	// dismissed again with three: it covers three
	s.UpdateSection(eng, fd, "Description", "a TODO here and a TODO there and one more TODO", "", alice)
	checked(t, s, fd)
	if err := s.DismissWhy(eng, fd, "todo", "section:Description", "TODO", "three are fine", uBob); err != nil {
		t.Fatal(err)
	}
	if n := covers(); n != 3 {
		t.Fatalf("the second dismissal covers %d, want 3", n)
	}
	if open() != 0 || stored() != 0 {
		t.Fatalf("dismissed again: open %d, stored %d", open(), stored())
	}
}

// A dismissal made before counts were kept (covers 0) covers its row as it
// did, until a check finds the row: that run writes the count it found.
func TestDismissalWithoutCountIsSettledByACheck(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, todoRule)
	fid := load(t, s, fd).F.Meta.ID
	qh := ViolationHash("section:Description", "TODO")
	s.UpdateSection(eng, fd, "Description", "a TODO here and a TODO there", "", alice)
	if err := s.DB().TxFor(eng, func(tx *db.Tx) error {
		return tx.Dismiss(db.Dismissal{Eng: eng, Fid: fid, Rule: "todo", QuoteHash: qh, Level: "error", By: "bob", Reason: "old"})
	}); err != nil {
		t.Fatal(err)
	}
	if vs, err := s.OpenChecks(eng, fd); err != nil || len(vs) != 0 {
		t.Fatalf("an old dismissal no longer covers: %+v %v", vs, err)
	}
	checked(t, s, fd)
	ds, _ := s.Dismissals(eng, fid)
	if d := ds[db.DismissKey("todo", qh)]; d.Covers != 2 || d.Reason != "old" || d.By != "bob" {
		t.Fatalf("after the check: %+v", d)
	}
	s.UpdateSection(eng, fd, "Description", "TODO TODO TODO", "", alice)
	if vs, _ := s.OpenChecks(eng, fd); len(vs) != 1 {
		t.Fatalf("a third match after the count was written: %+v", vs)
	}
}
