package db

import (
	"database/sql"
	"testing"
	"time"

	"github.com/abno525/yars/internal/chat"
)

func TestSchemaV4(t *testing.T) {
	d, _ := open(t)
	if schemaVersion < 4 {
		t.Fatalf("schema %d", schemaVersion)
	}
	for _, tb := range []string{"check_runs", "check_results", "dismissals"} {
		var n int
		if err := d.QueryRow("SELECT count(*) FROM " + tb).Scan(&n); err != nil {
			t.Fatalf("%s: %v", tb, err)
		}
	}
}

func TestChatKindRoundTrip(t *testing.T) {
	d, _ := open(t)
	m := chat.Message{ID: "c1", TS: time.Now().UTC(), User: "yars", Text: "t", Section: "Impact", Kind: chat.KindCheck}
	if err := d.TxFor("e", func(tx *Tx) error { return tx.AddMessage("e", "F-001", m) }); err != nil {
		t.Fatal(err)
	}
	got, err := d.Messages("e", "F-001")
	if err != nil || len(got) != 1 || got[0].Kind != chat.KindCheck || got[0].Section != "Impact" {
		t.Fatalf("got %+v %v", got, err)
	}
}

// Q13: a run stores the rules' version; a run from before v19 has none ("")
// and keeps counting as it did.
func TestRunsFromBeforeV19StillCount(t *testing.T) {
	p := openAtVersion(t, 18)
	raw, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec("INSERT INTO check_runs(eng, fid, content_hash, started, finished, state, by_user) VALUES ('e', 'F-001', 'h', 'x', 'y', 'done', 'bob')"); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	r, ok, err := d.LatestRun("e", "F-001")
	if err != nil || !ok || r.Rules != "" || r.ContentHash != "h" {
		t.Fatalf("old run %+v %v %v", r, ok, err)
	}
	id, err := d.StartRun("e", "F-002", "h", "bob", "0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if r, err := d.Run(id); err != nil || r.Rules != "0123456789abcdef" {
		t.Fatalf("new run %+v %v", r, err)
	}
	runs, err := d.LatestRuns([][2]string{{"e", "F-001"}, {"e", "F-002"}})
	if err != nil || runs["e/F-001"].Rules != "" || runs["e/F-002"].Rules != "0123456789abcdef" {
		t.Fatalf("latest runs %+v %v", runs, err)
	}
}

// Q11: which runs have an AI step that could not run.
func TestFailedAIRuns(t *testing.T) {
	d, _ := open(t)
	a, _ := d.StartRun("e", "F-001", "h", "bob", "")
	b, _ := d.StartRun("e", "F-002", "h", "bob", "")
	c, _ := d.StartRun("e", "F-003", "h", "bob", "")
	if err := d.AddSteps([]CheckStep{
		{RunID: a, Pos: 0, Rule: "ai1", Kind: "ai", State: StepFailed},
		{RunID: b, Pos: 0, Rule: "ai1", Kind: "ai", State: StepPass},
		{RunID: b, Pos: 1, Rule: "sh", Kind: "script", State: StepFailed},
		{RunID: c, Pos: 0, Rule: "ai1", Kind: "ai", State: StepHits},
	}); err != nil {
		t.Fatal(err)
	}
	got, err := d.FailedAIRuns([]int64{a, b, c})
	if err != nil || len(got) != 1 || !got[a] {
		t.Fatalf("failed AI runs %v %v", got, err)
	}
	if got, err := d.FailedAIRuns(nil); err != nil || len(got) != 0 {
		t.Fatalf("none asked: %v %v", got, err)
	}
}

func TestCheckRunLifecycle(t *testing.T) {
	d, _ := open(t)
	if _, ok, err := d.LatestRun("e", "F-001"); ok || err != nil {
		t.Fatalf("run before start: %v %v", ok, err)
	}
	id, err := d.StartRun("e", "F-001", "h1", "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RunProgress(id, 2, 5); err != nil {
		t.Fatal(err)
	}
	r, ok, err := d.LatestRun("e", "F-001")
	if !ok || err != nil || r.State != RunRunning || r.Done != 2 || r.Total != 5 || r.By != "alice" || r.ContentHash != "h1" {
		t.Fatalf("running %+v %v %v", r, ok, err)
	}
	res := []CheckResult{{Rule: "a", Level: "error", Message: "m", Target: "section:Impact", Quote: "q", QuoteHash: "qh", Thread: "c1"}}
	if err := d.TxFor("e", func(tx *Tx) error { return tx.FinishRun(id, RunFailed, "invalid output", res) }); err != nil {
		t.Fatal(err)
	}
	r, _, _ = d.LatestRun("e", "F-001")
	if r.State != RunFailed || r.Error != "invalid output" || r.Finished == "" {
		t.Fatalf("finished %+v", r)
	}
	got, err := d.RunResults(id)
	if err != nil || len(got) != 1 || got[0] != (CheckResult{RunID: id, Rule: "a", Level: "error", Message: "m", Target: "section:Impact", Quote: "q", QuoteHash: "qh", Thread: "c1", Matches: 1}) {
		t.Fatalf("results %+v %v", got, err)
	}
	var th []CheckThreadRef
	d.TxFor("e", func(tx *Tx) error { th, err = tx.CheckThreadRefs("e", "F-001"); return err })
	if len(th) != 1 || th[0] != (CheckThreadRef{Rule: "a", QuoteHash: "qh", Thread: "c1"}) {
		t.Fatalf("threads %+v", th)
	}
	// purge drops runs, results and dismissals
	d.TxFor("e", func(tx *Tx) error {
		return tx.Dismiss(Dismissal{Eng: "e", Fid: "F-001", Rule: "a", QuoteHash: "qh", Level: "error", By: "bob"})
	})
	if err := d.TxFor("e", func(tx *Tx) error { return tx.Purge("e") }); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := d.LatestRun("e", "F-001"); ok {
		t.Fatal("run survived purge")
	}
	if ds, _ := d.Dismissals("e", "F-001"); len(ds) != 0 {
		t.Fatal("dismissal survived purge")
	}
}

// A renamed rule's dismissals move to the new ID in every engagement, and so
// do the results and steps of its stored runs. Where the new ID has a
// dismissal for the same place already, that one stays and the old one goes:
// nothing is left under the old ID.
func TestRenameRule(t *testing.T) {
	d, _ := open(t)
	for _, x := range []Dismissal{
		{Eng: "e", Fid: "F-001", Rule: "old", QuoteHash: "q1", Level: "error", By: "bob", Reason: "r1"},
		{Eng: "e", Fid: "F-001", Rule: "old", QuoteHash: "q2", Level: "error", By: "bob", Reason: "r2"},
		{Eng: "e", Fid: "F-001", Rule: "new", QuoteHash: "q2", Level: "error", By: "dora", Reason: "kept"},
		{Eng: "e", Fid: "F-001", Rule: "other", QuoteHash: "q1", Level: "error", By: "bob"},
		{Eng: "f", Fid: "F-001", Rule: "old", QuoteHash: "q1", Level: "warning", By: "alice"},
	} {
		if err := d.TxFor(x.Eng, func(tx *Tx) error { return tx.Dismiss(x) }); err != nil {
			t.Fatal(err)
		}
	}
	// a stored run with results and a step of the old rule, and of another
	run, err := d.StartRun("f", "F-001", "h", "alice", "v1")
	if err != nil {
		t.Fatal(err)
	}
	d.AddSteps([]CheckStep{{RunID: run, Pos: 0, Rule: "old", State: StepHits, Hits: 1}, {RunID: run, Pos: 1, Rule: "other", State: StepHits, Hits: 1}})
	if err := d.TxFor("f", func(tx *Tx) error {
		return tx.FinishRun(run, RunDone, "", []CheckResult{
			{Rule: "old", Level: "warning", Message: "m", Target: "title", Quote: "q", QuoteHash: "q1", Thread: "c1"},
			{Rule: "other", Level: "error", Message: "m", Target: "title", Quote: "q", QuoteHash: "q1", Thread: "c2"}})
	}); err != nil {
		t.Fatal(err)
	}
	n, err := d.RenameRule("old", "new")
	if err != nil || n != 2 {
		t.Fatalf("moved %d, %v", n, err)
	}
	e, _ := d.Dismissals("e", "F-001")
	f, _ := d.Dismissals("f", "F-001")
	if len(e) != 3 || e[DismissKey("new", "q1")].Reason != "r1" || e[DismissKey("new", "q2")].By != "dora" || e[DismissKey("other", "q1")].By != "bob" ||
		len(f) != 1 || f[DismissKey("new", "q1")].By != "alice" {
		t.Fatalf("e %+v\nf %+v", e, f)
	}
	// the stored run's results and steps are the new rule's: the dismissed
	// result is not counted, and its thread is the new rule's
	res, _ := d.RunResults(run)
	steps, _ := d.RunSteps(run)
	if len(res) != 2 || res[0].Rule != "new" || res[0].Thread != "c1" || res[1].Rule != "other" ||
		len(steps) != 2 || steps[0].Rule != "new" || steps[0].Hits != 1 || steps[1].Rule != "other" {
		t.Fatalf("results %+v\nsteps %+v", res, steps)
	}
	if runs, err := d.LatestRuns([][2]string{{"f", "F-001"}}); err != nil || runs["f/F-001"].Warnings != 0 || runs["f/F-001"].Errors != 1 {
		t.Fatalf("counts %+v %v", runs, err)
	}
	if n, err := d.RenameRule("old", "new"); err != nil || n != 0 {
		t.Fatalf("a second move: %d, %v", n, err)
	}
}

func TestDismissals(t *testing.T) {
	d, _ := open(t)
	ds := Dismissal{Eng: "e", Fid: "F-001", Rule: "a", QuoteHash: "qh", Level: "warning", By: "alice"}
	if err := d.TxFor("e", func(tx *Tx) error { return tx.Dismiss(ds) }); err != nil {
		t.Fatal(err)
	}
	got, err := d.Dismissals("e", "F-001")
	if err != nil || got[DismissKey("a", "qh")].By != "alice" || got[DismissKey("a", "qh")].At == "" {
		t.Fatalf("got %+v %v", got, err)
	}
	if err := d.TxFor("e", func(tx *Tx) error { return tx.Undismiss("e", "F-001", "a", "qh") }); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.Dismissals("e", "F-001"); len(got) != 0 {
		t.Fatalf("after undismiss %+v", got)
	}
}
