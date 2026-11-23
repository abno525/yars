package db

import (
	"testing"
	"time"

	"yars/internal/chat"
)

func TestChatStamp(t *testing.T) {
	d, _ := open(t)
	s0, err := d.ChatStamp("acme", "F-001")
	if err != nil || s0 != "0.0" {
		t.Fatalf("empty stamp %q %v", s0, err)
	}
	add := func(eng, fid, id string) {
		t.Helper()
		if err := d.TxFor(eng, func(tx *Tx) error {
			return tx.AddMessage(eng, fid, chat.Message{ID: id, TS: time.Now(), User: "bob", Text: "x"})
		}); err != nil {
			t.Fatal(err)
		}
	}
	add("acme", "F-001", "a")
	s1, _ := d.ChatStamp("acme", "F-001")
	if s1 == s0 {
		t.Fatal("stamp unchanged by a post")
	}
	add("acme", "F-002", "b") // another finding
	if s, _ := d.ChatStamp("acme", "F-001"); s != s1 {
		t.Fatalf("other finding moved the stamp: %q -> %q", s1, s)
	}
	add("acme", "F-001", "c")
	if s, _ := d.ChatStamp("acme", "F-001"); s == s1 {
		t.Fatal("stamp unchanged by a second post")
	}
}
