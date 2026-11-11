package db

import "testing"

// LatestRuns reads the newest run of many findings in one query, with its
// counts of errors and warnings that are not dismissed (notices about the
// rules themselves do not count).
func TestLatestRuns(t *testing.T) {
	d, _ := open(t)
	old, _ := d.StartRun("e", "F-001", "h0", "alice", "")
	d.TxFor("e", func(tx *Tx) error {
		return tx.FinishRun(old, RunDone, "", []CheckResult{{Rule: "r", Level: "error", QuoteHash: "q0"}})
	})
	id, _ := d.StartRun("e", "F-001", "h1", "alice", "")
	err := d.TxFor("e", func(tx *Tx) error {
		if err := tx.FinishRun(id, RunDone, "", []CheckResult{
			{Rule: "r1", Level: "error", QuoteHash: "a"},
			{Rule: "r1", Level: "error", QuoteHash: "a"}, // stored twice before runs kept one row
			{Rule: "r2", Level: "error", QuoteHash: "b"},
			{Rule: "r3", Level: "warning", QuoteHash: "c"},
			{Rule: "ai", Level: "warning", Target: "ai", QuoteHash: "d"},
		}); err != nil {
			return err
		}
		return tx.Dismiss(Dismissal{Eng: "e", Fid: "F-001", Rule: "r2", QuoteHash: "b", Level: "error", By: "bob"})
	})
	if err != nil {
		t.Fatal(err)
	}
	run2, _ := d.StartRun("x", "F-002", "h2", "alice", "") // still running
	got, err := d.LatestRuns([][2]string{{"e", "F-001"}, {"x", "F-002"}, {"e", "F-009"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("runs %+v", got)
	}
	r := got["e/F-001"]
	if r.ID != id || r.State != RunDone || r.ContentHash != "h1" || r.Errors != 1 || r.Warnings != 1 {
		t.Fatalf("F-001 %+v", r)
	}
	if r := got["x/F-002"]; r.ID != run2 || r.State != RunRunning {
		t.Fatalf("F-002 %+v", r)
	}
	if got, err := d.LatestRuns(nil); err != nil || len(got) != 0 {
		t.Fatalf("none %+v %v", got, err)
	}
}
