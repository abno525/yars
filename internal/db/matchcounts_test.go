package db

import "testing"

// A database from before match counts (schema 30) comes up with its
// dismissal still covering its row: the stored result reads as one match,
// the dismissal as "made before counts were kept", which covers any number
// (pre1 7.9). The step can run again on a database that has the columns.
func TestMatchCountsMigration(t *testing.T) {
	d, _ := open(t)
	id, err := d.StartRun("acme", "F-001", "hash", "alice", "v1")
	if err != nil {
		t.Fatal(err)
	}
	qh := ViolationHash("section:Impact", "TODO")
	if err := d.Tx(func(tx *Tx) error {
		if err := tx.FinishRun(id, RunDone, "", []CheckResult{{Rule: "todo", Level: "error", Message: "m", Target: "section:Impact", Quote: "TODO", QuoteHash: qh, Matches: 3}}); err != nil {
			return err
		}
		return tx.Dismiss(Dismissal{Eng: "acme", Fid: "F-001", Rule: "todo", QuoteHash: qh, Level: "error", By: "bob", Reason: "fine", Covers: 3})
	}); err != nil {
		t.Fatal(err)
	}
	// as schema 30 had the two tables
	for _, q := range []string{"ALTER TABLE dismissals DROP COLUMN covers", "ALTER TABLE check_results DROP COLUMN matches"} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		rerun(t, d, "031-match-counts")
		ds, err := d.Dismissals("acme", "F-001")
		if err != nil {
			t.Fatal(err)
		}
		x, ok := Covering(ds, "todo", "section:Impact", "TODO", 500)
		if !ok || x.Covers != 0 || x.By != "bob" || x.Reason != "fine" {
			t.Fatalf("the dismissal after the upgrade: %+v %v", x, ok)
		}
		res, err := d.RunResults(id)
		if err != nil || len(res) != 1 || res[0].Matches != 1 {
			t.Fatalf("the stored result after the upgrade: %+v %v", res, err)
		}
		runs, err := d.LatestRuns([][2]string{{"acme", "F-001"}})
		if err != nil || runs["acme/F-001"].Errors != 0 {
			t.Fatalf("the dismissed row counts as open: %+v %v", runs, err)
		}
	}
}

// The stored count of open results follows the dismissal's count: a row
// that stands for more matches than its dismissal covered is open.
func TestLatestRunsCountsARowThatGrew(t *testing.T) {
	d, _ := open(t)
	qh := ViolationHash("section:Impact", "TODO")
	run := func(matches int) {
		t.Helper()
		id, err := d.StartRun("acme", "F-001", "hash", "alice", "v1")
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Tx(func(tx *Tx) error {
			return tx.FinishRun(id, RunDone, "", []CheckResult{{Rule: "todo", Level: "error", Message: "m", Target: "section:Impact", Quote: "TODO", QuoteHash: qh, Matches: matches}})
		}); err != nil {
			t.Fatal(err)
		}
	}
	open := func() int {
		t.Helper()
		runs, err := d.LatestRuns([][2]string{{"acme", "F-001"}})
		if err != nil {
			t.Fatal(err)
		}
		return runs["acme/F-001"].Errors
	}
	run(2)
	if err := d.Tx(func(tx *Tx) error {
		return tx.Dismiss(Dismissal{Eng: "acme", Fid: "F-001", Rule: "todo", QuoteHash: qh, Level: "error", By: "bob", Covers: 2})
	}); err != nil {
		t.Fatal(err)
	}
	if n := open(); n != 0 {
		t.Fatalf("covered: %d open", n)
	}
	run(3)
	if n := open(); n != 1 {
		t.Fatalf("a third match: %d open", n)
	}
	run(1)
	if n := open(); n != 0 {
		t.Fatalf("fewer matches: %d open", n)
	}
}
