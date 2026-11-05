package db

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"

	"yars/internal/chat"
)

// TxFor bumps the engagement's own counter and the global one.
func TestTxForBumpsEngagementSeq(t *testing.T) {
	d, _ := open(t)
	g0, _ := d.Seq()
	if s, _ := d.SeqFor("acme"); s != 0 {
		t.Fatalf("fresh seq %d", s)
	}
	seq, err := d.TxForSeq("acme", func(tx *Tx) error { return nil })
	if err != nil || seq != 1 {
		t.Fatalf("seq %d %v", seq, err)
	}
	d.TxFor("acme", func(tx *Tx) error { return nil })
	if s, _ := d.SeqFor("acme"); s != 2 {
		t.Fatalf("acme seq %d", s)
	}
	if s, _ := d.SeqFor("other"); s != 0 {
		t.Fatalf("other seq %d", s)
	}
	if g, _ := d.Seq(); g != g0+2 {
		t.Fatalf("global %d -> %d", g0, g)
	}
	all, err := d.EngSeqs()
	if err != nil || len(all) != 1 || all["acme"] != 2 {
		t.Fatalf("all %v %v", all, err)
	}
}

// Writes to an engagement's state or chat bump its counter even through a
// plain Tx; account changes bump only the global counter.
func TestTxTouchesEngagements(t *testing.T) {
	d, _ := open(t)
	d.Tx(func(tx *Tx) error { return tx.PutState("acme", "F-001", State{Status: "complete"}) })
	d.Tx(func(tx *Tx) error {
		return tx.AddMessage("beta", "F-001", chat.Message{ID: "m1", User: "bob", Text: "x"})
	})
	d.Tx(func(tx *Tx) error { return tx.Purge("gamma") })
	d.Tx(func(tx *Tx) error { return nil })
	all, _ := d.EngSeqs()
	if all["acme"] != 1 || all["beta"] != 1 || all["gamma"] != 1 || len(all) != 3 {
		t.Fatalf("seqs %v", all)
	}
}

// A failed transaction bumps nothing.
func TestTxForRollback(t *testing.T) {
	d, _ := open(t)
	g0, _ := d.Seq()
	if _, err := d.TxForSeq("acme", func(tx *Tx) error { return sql.ErrNoRows }); err == nil {
		t.Fatal("expected error")
	}
	if s, _ := d.SeqFor("acme"); s != 0 {
		t.Fatalf("seq %d", s)
	}
	if g, _ := d.Seq(); g != g0 {
		t.Fatal("global bumped")
	}
}

func TestTxForConcurrent(t *testing.T) {
	d, _ := open(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				if err := d.TxFor("acme", func(tx *Tx) error { return nil }); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if s, _ := d.SeqFor("acme"); s != 80 {
		t.Fatalf("seq %d", s)
	}
}

// A v1 database (one global counter) is upgraded in place.
func TestMigrateV1(t *testing.T) {
	p := filepath.Join(t.TempDir(), "yars.db")
	raw, err := sql.Open("sqlite", "file:"+p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(migrations[0]); err != nil {
		t.Fatal(err)
	}
	raw.Exec("PRAGMA user_version = 1")
	raw.Exec("UPDATE changes SET seq = 7")
	raw.Close()
	d, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if g, _ := d.Seq(); g != 7 {
		t.Fatalf("global seq %d", g)
	}
	if err := d.TxFor("acme", func(tx *Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if s, _ := d.SeqFor("acme"); s != 1 {
		t.Fatalf("seq %d", s)
	}
}

func TestPragmas(t *testing.T) {
	d, _ := open(t)
	for _, c := range []struct {
		pragma string
		want   int64
	}{{"synchronous", 1}, {"cache_size", -20000}, {"mmap_size", 134217728}, {"busy_timeout", 5000}, {"foreign_keys", 1}} {
		var got int64
		if err := d.QueryRow("PRAGMA " + c.pragma).Scan(&got); err != nil || got != c.want {
			t.Errorf("%s = %d (%v), want %d", c.pragma, got, err, c.want)
		}
	}
	if n := d.Stats().MaxOpenConnections; n != 8 {
		t.Errorf("max open %d", n)
	}
}
