package db

import (
	"errors"
	"testing"
)

// DropRun removes a running run with its steps, so the run before it is the
// finding's newest again; a run that ended stays, and so does a run that is
// gone already.
func TestDropRun(t *testing.T) {
	d, _ := open(t)
	old, _ := d.StartRun("e", "F-001", "h0", "alice", "")
	if err := d.TxFor("e", func(tx *Tx) error {
		return tx.FinishRun(old, RunDone, "", []CheckResult{{Rule: "r", Level: "error", QuoteHash: "q0"}})
	}); err != nil {
		t.Fatal(err)
	}
	id, _ := d.StartRun("e", "F-001", "h1", "alice", "")
	if err := d.AddSteps([]CheckStep{{RunID: id, Pos: 0, Rule: "r", Kind: "script", State: StepRunning}}); err != nil {
		t.Fatal(err)
	}
	if gone, err := d.DropRun(old); err != nil || gone {
		t.Fatalf("a finished run: %v %v", gone, err)
	}
	if gone, err := d.DropRun(id); err != nil || !gone {
		t.Fatalf("a running run: %v %v", gone, err)
	}
	if _, err := d.Run(id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the run stays: %v", err)
	}
	if steps, err := d.RunSteps(id); err != nil || len(steps) != 0 {
		t.Fatalf("its steps stay: %+v %v", steps, err)
	}
	if run, ok, err := d.LatestRun("e", "F-001"); err != nil || !ok || run.ID != old {
		t.Fatalf("latest %+v %v %v", run, ok, err)
	}
	if res, err := d.RunResults(old); err != nil || len(res) != 1 {
		t.Fatalf("the earlier run's results: %+v %v", res, err)
	}
	if gone, err := d.DropRun(id); err != nil || gone {
		t.Fatalf("a run that is gone: %v %v", gone, err)
	}
}
