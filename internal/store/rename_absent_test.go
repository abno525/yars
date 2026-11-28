package store

import (
	"testing"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/rules"
)

const needLocation = "- id: need-loc\n  target: details:Location\n  regex_require: '.'\n  require_nonempty: true\n  message: Say where\n"

// A finding that has no value under a renamed details row is not rewritten,
// but what is stored for it under the old name moves all the same: the
// dismissed "empty" row of a rule on that place stays dismissed (pre1 7.11).
func TestRenameMovesResultsOfAnUnchangedFinding(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, needLocation)
	mine := func() []rules.Violation {
		t.Helper()
		open, err := s.OpenChecks(eng, fd)
		if err != nil {
			t.Fatal(err)
		}
		var out []rules.Violation
		for _, v := range open {
			if v.Rule == "need-loc" {
				out = append(out, v)
			}
		}
		return out
	}
	checked(t, s, fd)
	open := mine()
	if len(open) != 1 || open[0].Target != "details:Location" {
		t.Fatalf("before the dismissal: %+v", open)
	}
	quote := open[0].Quote
	if err := s.DismissWhy(eng, fd, "need-loc", "details:Location", quote, "not known", uBob); err != nil {
		t.Fatal(err)
	}
	if open := mine(); len(open) != 0 {
		t.Fatalf("dismissed: %+v", open)
	}
	before := raw(t, dir, eng, fd)
	changed, err := s.RenameNames("details row", map[string]string{"Location": "Where"}, alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 0 || raw(t, dir, eng, fd) != before {
		t.Fatalf("a finding without the row was rewritten: %v", changed)
	}
	// the Structure save renames the rule's target in the same step
	withRules(t, s, dir, "- id: need-loc\n  target: details:Where\n  regex_require: '.'\n  require_nonempty: true\n  message: Say where\n")
	if open := mine(); len(open) != 0 {
		t.Fatalf("the dismissed row is open again after the rename: %+v", open)
	}
	fid := load(t, s, fd).F.Meta.ID
	ds, _ := s.Dismissals(eng, fid)
	if d, ok := ds[db.DismissKey("need-loc", ViolationHash("details:Where", quote))]; !ok || d.By != "bob" || len(ds) != 1 {
		t.Fatalf("dismissals after the rename: %+v", ds)
	}
	// a second rename of the same names finds nothing left to move
	if _, err := s.RenameNames("details row", map[string]string{"Location": "Where"}, alice); err != nil {
		t.Fatal(err)
	}
	if ds2, _ := s.Dismissals(eng, fid); len(ds2) != 1 {
		t.Fatalf("dismissals after a second rename: %+v", ds2)
	}
}
