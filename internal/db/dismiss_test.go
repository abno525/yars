package db

import (
	"testing"
)

// v14: stored results get per-row keys, and an old quote-only dismissal a
// copy for each place a run found its quote (so stored counts keep
// skipping it); the old row stays for places no run stored.
func TestPerRowDismissalsMigration(t *testing.T) {
	d := openTest(t)
	id, err := d.StartRun("e", "F-001", "h", "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	old := LegacyHash("TODO")
	d.TxFor("e", func(tx *Tx) error {
		if err := tx.FinishRun(id, RunDone, "", []CheckResult{
			{Rule: "todo", Level: "error", Target: "section:Description", Quote: "TODO", QuoteHash: old},
			{Rule: "todo", Level: "error", Target: "section:Remediation", Quote: "TODO", QuoteHash: old},
		}); err != nil {
			return err
		}
		return tx.Dismiss(Dismissal{Eng: "e", Fid: "F-001", Rule: "todo", QuoteHash: old, Level: "error", By: "bob"})
	})
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := perRowDismissals(tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	res, _ := d.RunResults(id)
	for _, r := range res {
		if r.QuoteHash != ViolationHash(r.Target, r.Quote) {
			t.Fatalf("not rehashed: %+v", r)
		}
	}
	ds, _ := d.Dismissals("e", "F-001")
	for _, place := range []string{"section:Description", "section:Remediation"} {
		if ds[DismissKey("todo", ViolationHash(place, "TODO"))].By != "bob" {
			t.Fatalf("no copy for %s: %+v", place, ds)
		}
	}
	if _, ok := ds[DismissKey("todo", old)]; !ok {
		t.Fatal("old row dropped")
	}
	runs, _ := d.LatestRuns([][2]string{{"e", "F-001"}})
	if runs["e/F-001"].Errors != 0 {
		t.Fatalf("counts %+v", runs)
	}
	// the place no run stored is still covered by the old row
	if _, ok := Lookup(ds, "todo", "section:Impact", "TODO"); !ok {
		t.Fatal("old dismissal lost")
	}
}

// v18: a run v13 marked stored though it was cut off without results (it
// failed before its first rule, or after its last but before storing) is
// not a finished run: it does not hide the finished run before it.
func TestCutOffRunsNotStored(t *testing.T) {
	d := openTest(t)
	done, _ := d.StartRun("e", "F-001", "h", "bob", "")
	d.TxFor("e", func(tx *Tx) error {
		return tx.FinishRun(done, RunDone, "", []CheckResult{{Rule: "ai", Level: "error", Target: "section:Impact", Quote: "q", QuoteHash: "x"}})
	})
	clean, _ := d.StartRun("e", "F-001", "h", "bob", "")
	d.TxFor("e", func(tx *Tx) error { return tx.FinishRun(clean, RunDone, "", nil) })
	for _, total := range []int{0, 3} {
		id, _ := d.StartRun("e", "F-001", "h", "bob", "")
		// as v13 left them: failed by FailRun, marked stored
		if _, err := d.Exec("UPDATE check_runs SET state = ?, error = 'interrupted', finished = 'x', total = ?, done_count = ?, stored = 1 WHERE id = ?", RunFailed, total, total, id); err != nil {
			t.Fatal(err)
		}
	}
	rerun(t, d, "018-cut-off-runs-not-stored")
	runs, err := d.FinishedRuns("e", "F-001", "h", 10)
	if err != nil || len(runs) != 2 || runs[0].ID != clean || runs[1].ID != done {
		t.Fatalf("finished runs %+v %v", runs, err)
	}
}

// v17: an old quote-only dismissal that has its copies for the places runs
// stored ends (D18: the same wording in a new place counts); one no run
// ever stored a result for stays (nothing tells its place yet).
func TestLegacyDismissalsEnd(t *testing.T) {
	d := openTest(t)
	id, err := d.StartRun("e", "F-001", "h", "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	place := ViolationHash("section:Impact", "TODO")
	d.TxFor("e", func(tx *Tx) error {
		if err := tx.FinishRun(id, RunDone, "", []CheckResult{{Rule: "todo", Level: "error", Target: "section:Impact", Quote: "TODO", QuoteHash: place}}); err != nil {
			return err
		}
		for _, x := range []Dismissal{
			{Eng: "e", Fid: "F-001", Rule: "todo", QuoteHash: LegacyHash("TODO"), Level: "error", By: "bob"},
			{Eng: "e", Fid: "F-001", Rule: "todo", QuoteHash: place, Level: "error", By: "bob"},
			{Eng: "e", Fid: "F-001", Rule: "fast", QuoteHash: LegacyHash("x"), Level: "error", By: "bob"},
		} {
			if err := tx.Dismiss(x); err != nil {
				return err
			}
		}
		return nil
	})
	// a database at v16 (already past v14) gets it too
	rerun(t, d, "017-end-copied-legacy-dismissals")
	ds, _ := d.Dismissals("e", "F-001")
	if _, ok := ds[DismissKey("todo", LegacyHash("TODO"))]; ok {
		t.Fatalf("copied old dismissal kept: %+v", ds)
	}
	if _, ok := ds[DismissKey("todo", place)]; !ok {
		t.Fatalf("copy dropped: %+v", ds)
	}
	if _, ok := Lookup(ds, "todo", "section:Remediation", "TODO"); ok {
		t.Fatal("old dismissal still covers a new place")
	}
	if _, ok := ds[DismissKey("fast", LegacyHash("x"))]; !ok {
		t.Fatalf("old dismissal without stored results dropped: %+v", ds)
	}
}
