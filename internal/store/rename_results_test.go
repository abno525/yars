package store

import (
	"testing"

	"github.com/abno525/yars/internal/db"
)

// A renamed section takes what is stored for the finding under its old name
// along: the results of its check runs and their dismissals. A row dismissed
// before the rename stays dismissed, and the strip lists it once (pre1
// 7.11).
func TestRenameKeepsDismissalsAndResults(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, todoRule)
	if err := s.UpdateSection(eng, fd, "Impact", "a TODO here", "", alice); err != nil {
		t.Fatal(err)
	}
	checked(t, s, fd)
	if err := s.DismissWhy(eng, fd, "todo", "section:Impact", "TODO", "fine here", uBob); err != nil {
		t.Fatal(err)
	}
	if open, err := s.OpenChecks(eng, fd); err != nil || len(open) != 0 {
		t.Fatalf("before the rename: %+v %v", open, err)
	}
	if _, err := s.RenameNames("section", toBusiness, alice); err != nil {
		t.Fatal(err)
	}
	open, err := s.OpenChecks(eng, fd)
	if err != nil || len(open) != 0 {
		t.Fatalf("the dismissed row is open again after the rename: %+v %v", open, err)
	}
	items, err := s.CheckItems(eng, fd)
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, v := range items {
		if v.Rule == "todo" {
			rows++
			if v.Target != "section:Business impact" {
				t.Fatalf("a row under the old name: %+v", v)
			}
		}
	}
	if rows != 1 {
		t.Fatalf("the strip lists the row %d times: %+v", rows, items)
	}
	fid := load(t, s, fd).F.Meta.ID
	ds, _ := s.Dismissals(eng, fid)
	if d, ok := ds[db.DismissKey("todo", ViolationHash("section:Business impact", "TODO"))]; !ok || d.By != "bob" || d.Reason != "fine here" || len(ds) != 1 {
		t.Fatalf("dismissals after the rename: %+v", ds)
	}
	if runs, err := s.DB().LatestRuns([][2]string{{eng, fid}}); err != nil || runs[eng+"/"+fid].Errors != 0 {
		t.Fatalf("stored counts after the rename: %+v %v", runs, err)
	}
}
