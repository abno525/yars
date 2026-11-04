package db

import (
	"reflect"
	"testing"
	"time"

	"yars/internal/chat"
)

func TestStateDefaultsToDraft(t *testing.T) {
	d, _ := open(t)
	s, err := d.State("acme", "F-001")
	if err != nil || s.Status != "draft" || len(s.Reviewers) != 0 {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestStateRoundTrip(t *testing.T) {
	d, _ := open(t)
	want := State{Status: "verification", Reviewers: []Reviewer{{Name: "bob", ClearedHash: "h1"}, {Name: "carol"}},
		ReturnedBy: "bob", ReturnedReason: "add PoC", RetestSource: "old/F-001-x", RetestResult: "fixed", ApprovedHash: "h9"}
	if err := d.Tx(func(tx *Tx) error { return tx.PutState("acme", "F-001", want) }); err != nil {
		t.Fatal(err)
	}
	got, _ := d.State("acme", "F-001")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	// replacing drops reviewers no longer listed
	want.Reviewers = []Reviewer{{Name: "carol"}}
	d.Tx(func(tx *Tx) error { return tx.PutState("acme", "F-001", want) })
	if got, _ := d.State("acme", "F-001"); !reflect.DeepEqual(got.Reviewers, want.Reviewers) {
		t.Fatalf("reviewers %+v", got.Reviewers)
	}
	d.Tx(func(tx *Tx) error { return tx.PutState("acme", "F-002", State{Status: "complete"}) })
	all, _ := d.States("acme")
	if len(all) != 2 || all["F-002"].Status != "complete" || all["F-001"].Reviewers[0].Name != "carol" {
		t.Fatalf("all %+v", all)
	}
	if other, _ := d.States("other"); len(other) != 0 {
		t.Fatal("states leaked across engagements")
	}
}

func TestMessagesInOrder(t *testing.T) {
	d, _ := open(t)
	ts := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	m1 := chat.Message{ID: "a1", TS: ts, User: "bob", Text: "first", Section: "Impact"}
	m2 := chat.Message{ID: "a2", TS: ts, User: "alice", Reply: "a1", Text: "second"}
	m3 := chat.Message{ID: "a3", TS: ts, User: "bob", Event: "return", Text: "why"}
	err := d.Tx(func(tx *Tx) error {
		for _, m := range []chat.Message{m1, m2} {
			if err := tx.AddMessage("acme", "F-001", m); err != nil {
				return err
			}
		}
		return tx.AddMessage("acme", "F-002", m3)
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := d.Messages("acme", "F-001")
	if len(got) != 2 || !reflect.DeepEqual(got[0], m1) || !reflect.DeepEqual(got[1], m2) {
		t.Fatalf("got %+v", got)
	}
	all, _ := d.AllMessages("acme")
	if len(all["F-001"]) != 2 || !reflect.DeepEqual(all["F-002"], []chat.Message{m3}) {
		t.Fatalf("all %+v", all)
	}
	if err := d.Tx(func(tx *Tx) error { return tx.AddMessage("acme", "F-001", m1) }); err == nil {
		t.Fatal("duplicate message id accepted")
	}
}
