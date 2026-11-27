package db

import (
	"errors"
	"reflect"
	"testing"
)

var errStop = errors.New("stop")

// The journal keeps one row per finding, lists them in order, and loses a
// row in the transaction that makes its write. Other settings are not
// journal rows.
func TestIntentJournal(t *testing.T) {
	d, _ := open(t)
	if err := d.SetSetting("ai.model", "m1"); err != nil {
		t.Fatal(err)
	}
	rename := Intent{Eng: "beta", Fid: "F-002", Kind: IntentRename, Old: "o", New: "n", Sections: map[string]string{"Impact": "Business impact"}}
	for _, in := range []Intent{
		rename,
		{Eng: "acme", Fid: "F-001", Kind: IntentCarry, Old: "a", New: "b"},
		{Eng: "acme", Fid: "F-001", Kind: IntentCarry, Old: "b", New: "c"}, // in place of the one before
	} {
		if err := d.PutIntent(in); err != nil {
			t.Fatal(err)
		}
	}
	// a value that is no JSON, and a key without a finding
	if err := d.SetSetting("intent:acme/F-009", "{"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetSetting("intent:lonely", `{"kind":"carry"}`); err != nil {
		t.Fatal(err)
	}
	got, err := d.Intents()
	if err != nil || len(got) != 4 {
		t.Fatalf("journal %+v %v", got, err)
	}
	for i := range got {
		got[i].key = ""
	}
	want := []Intent{
		{Eng: "acme", Fid: "F-001", Kind: IntentCarry, Old: "b", New: "c"},
		{Eng: "acme", Fid: "F-009"},
		rename,
		{Eng: "lonely", Kind: IntentCarry},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("journal %+v\nwant    %+v", got, want)
	}
	// each row can be removed as it was listed, whatever its key reads as
	rows, _ := d.Intents()
	if err := d.Tx(func(tx *Tx) error { return tx.DropIntent("acme", "F-001") }); err != nil {
		t.Fatal(err)
	}
	if left, _ := d.Intents(); len(left) != 3 {
		t.Fatalf("after the write's transaction: %+v", left)
	}
	for _, in := range rows {
		if err := d.DropIntentRow(in); err != nil {
			t.Fatal(err)
		}
	}
	if left, err := d.Intents(); err != nil || len(left) != 0 {
		t.Fatalf("journal after the removals: %+v %v", left, err)
	}
	if v, _ := d.Setting("ai.model"); v != "m1" {
		t.Fatalf("another setting changed: %q", v)
	}
	// a transaction that fails keeps the row
	if err := d.PutIntent(rename); err != nil {
		t.Fatal(err)
	}
	failed := d.Tx(func(tx *Tx) error {
		if err := tx.DropIntent("beta", "F-002"); err != nil {
			return err
		}
		return errStop
	})
	if left, _ := d.Intents(); failed != errStop || len(left) != 1 {
		t.Fatalf("after a failed transaction: %+v (%v)", left, failed)
	}
}

// Changed tells whether statements inside a transaction wrote anything.
func TestTxChanged(t *testing.T) {
	d, _ := open(t)
	if err := d.Tx(func(tx *Tx) error {
		return tx.PutState("acme", "F-001", State{Status: "complete", ApprovedHash: "old"})
	}); err != nil {
		t.Fatal(err)
	}
	var none, some int64
	if err := d.TxFor("acme", func(tx *Tx) error {
		a, err := tx.Changed()
		if err != nil {
			return err
		}
		if err := tx.MoveHash("acme", "F-001", "other", "new"); err != nil {
			return err
		}
		b, _ := tx.Changed()
		if err := tx.MoveHash("acme", "F-001", "old", "new"); err != nil {
			return err
		}
		c, err := tx.Changed()
		none, some = b-a, c-b
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if none != 0 || some != 1 {
		t.Fatalf("changed %d for a move of nothing, %d for a move of the approval", none, some)
	}
}
