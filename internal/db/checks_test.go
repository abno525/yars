package db

import (
	"testing"
	"time"

	"yars/internal/chat"
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

func TestCheckRunLifecycle(t *testing.T) {
	d, _ := open(t)
	if _, ok, err := d.LatestRun("e", "F-001"); ok || err != nil {
		t.Fatalf("run before start: %v %v", ok, err)
	}
	id, err := d.StartRun("e", "F-001", "h1", "alice")
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
	if err != nil || len(got) != 1 || got[0] != (CheckResult{RunID: id, Rule: "a", Level: "error", Message: "m", Target: "section:Impact", Quote: "q", QuoteHash: "qh", Thread: "c1"}) {
		t.Fatalf("results %+v %v", got, err)
	}
	var th map[string]string
	d.TxFor("e", func(tx *Tx) error { th, err = tx.CheckThreads("e", "F-001"); return err })
	if th[DismissKey("a", "qh")] != "c1" {
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
