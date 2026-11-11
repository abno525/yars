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

// Q10: a rename moves the approval, the sign-offs and the check runs of a
// finding to its renamed content, and the comments on a renamed section.
func TestMoveHashAndRenameChatSection(t *testing.T) {
	d, _ := open(t)
	st := State{Status: "complete", ApprovedHash: "old", Reviewers: []Reviewer{{Name: "bob", ClearedHash: "old"}, {Name: "carol", ClearedHash: "other"}}}
	if err := d.Tx(func(tx *Tx) error {
		if err := tx.PutState("acme", "F-001", st); err != nil {
			return err
		}
		if err := tx.PutState("acme", "F-002", State{Status: "complete", ApprovedHash: "old"}); err != nil {
			return err
		}
		if err := tx.AddMessage("acme", "F-001", chat.Message{ID: "m1", User: "bob", Text: "x", Section: "Impact"}); err != nil {
			return err
		}
		return tx.AddMessage("acme", "F-001", chat.Message{ID: "m2", User: "bob", Text: "y", Section: "Description"})
	}); err != nil {
		t.Fatal(err)
	}
	run, _ := d.StartRun("acme", "F-001", "old", "bob", "")
	if err := d.TxFor("acme", func(tx *Tx) error {
		if err := tx.MoveHash("acme", "F-001", "old", "new"); err != nil {
			return err
		}
		return tx.RenameChatSection("acme", "F-001", "Impact", "Business impact")
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := d.State("acme", "F-001")
	if got.ApprovedHash != "new" || got.Reviewers[0].ClearedHash != "new" || got.Reviewers[1].ClearedHash != "other" {
		t.Fatalf("state %+v", got)
	}
	if other, _ := d.State("acme", "F-002"); other.ApprovedHash != "old" {
		t.Fatal("another finding moved")
	}
	if r, _ := d.Run(run); r.ContentHash != "new" {
		t.Fatalf("run hash %q", r.ContentHash)
	}
	ms, _ := d.Messages("acme", "F-001")
	if len(ms) != 2 || ms[0].Section != "Business impact" || ms[1].Section != "Description" {
		t.Fatalf("messages %+v", ms)
	}
}

func TestWithdrawnStateRoundTrip(t *testing.T) {
	d, _ := open(t)
	want := State{Status: "withdrawn", WithdrawnBy: "dora", WithdrawnReason: "duplicate of F-002"}
	if err := d.Tx(func(tx *Tx) error { return tx.PutState("acme", "F-001", want) }); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.State("acme", "F-001"); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestChatHiddenPerUser(t *testing.T) {
	d, _ := open(t)
	hide := func(user, fid, th string, on bool) {
		t.Helper()
		if err := d.SetChatHidden(user, "acme", fid, th, on); err != nil {
			t.Fatal(err)
		}
	}
	hide("bob", "F-001", "t1", true)
	hide("bob", "F-001", "t1", true) // idempotent
	hide("bob", "F-001", "t2", true)
	hide("bob", "F-002", "t9", true)
	hide("carol", "F-001", "t3", true)
	got, err := d.ChatHidden("bob", "acme", "F-001")
	if err != nil || len(got) != 2 || !got["t1"] || !got["t2"] {
		t.Fatalf("bob %v %v", got, err)
	}
	if got, _ := d.ChatHidden("carol", "acme", "F-001"); len(got) != 1 || !got["t3"] {
		t.Fatalf("carol %v", got)
	}
	if got, _ := d.ChatHidden("alice", "acme", "F-001"); len(got) != 0 {
		t.Fatalf("alice %v", got)
	}
	hide("bob", "F-001", "t1", false)
	if got, _ := d.ChatHidden("bob", "acme", "F-001"); len(got) != 1 || !got["t2"] {
		t.Fatalf("after show %v", got)
	}
	d.Tx(func(tx *Tx) error { return tx.Purge("acme") })
	if got, _ := d.ChatHidden("bob", "acme", "F-002"); len(got) != 0 {
		t.Fatalf("purge kept hidden threads %v", got)
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
