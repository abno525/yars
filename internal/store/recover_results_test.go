package store

import (
	"testing"

	"github.com/abno525/yars/internal/db"
)

// A structure rename stopped after a finding's commit: the next start moves
// the stored results and their dismissals to the renamed section too, so a
// row dismissed before the rename stays dismissed (pre1 7.11).
func TestRecoverMovesResultsAfterStop(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, todoRule)
	if err := s.UpdateSection(eng, fd, "Impact", "a TODO here", "", alice); err != nil {
		t.Fatal(err)
	}
	checked(t, s, fd)
	if err := s.DismissWhy(eng, fd, "todo", "section:Impact", "TODO", "fine here", uBob); err != nil {
		t.Fatal(err)
	}
	fid := load(t, s, fd).F.Meta.ID
	oldKey := db.DismissKey("todo", ViolationHash("section:Impact", "TODO"))
	newKey := db.DismissKey("todo", ViolationHash("section:Business impact", "TODO"))
	stopAfterCommit(t, s, func() { s.RenameNames("section", toBusiness, alice) })
	s2, _ := restarted(t, s)
	s2.Linter = s.Linter
	// the leftover: the heading is renamed, the dismissal is under the old one
	if ds, _ := s2.Dismissals(eng, fid); len(ds) != 1 || ds[oldKey].By != "bob" {
		t.Fatalf("after the stop: %+v", ds)
	}
	if open, err := s2.OpenChecks(eng, fd); err != nil || len(open) != 1 {
		t.Fatalf("after the stop the row is not open: %+v %v", open, err)
	}
	res := recovered(t, s2)
	if len(res.Replayed) != 1 || len(res.Unreplayed) != 0 {
		t.Fatalf("result %+v", res)
	}
	ds, _ := s2.Dismissals(eng, fid)
	if d, ok := ds[newKey]; !ok || d.By != "bob" || d.Reason != "fine here" || len(ds) != 1 {
		t.Fatalf("dismissals after the start: %+v", ds)
	}
	if open, err := s2.OpenChecks(eng, fd); err != nil || len(open) != 0 {
		t.Fatalf("the dismissed row is open after the start: %+v %v", open, err)
	}
	items, err := s2.CheckItems(eng, fd)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range items {
		if v.Rule == "todo" && v.Target != "section:Business impact" {
			t.Fatalf("a row under the old name: %+v", v)
		}
	}
}
