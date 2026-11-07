package db

import "testing"

// v14: stored results get per-row keys, and an old quote-only dismissal a
// copy for each place a run found its quote (so stored counts keep
// skipping it); the old row stays for places no run stored.
func TestPerRowDismissalsMigration(t *testing.T) {
	d := openTest(t)
	id, err := d.StartRun("e", "F-001", "h", "bob")
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
