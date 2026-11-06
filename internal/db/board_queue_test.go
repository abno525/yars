package db

import (
	"fmt"
	"testing"
)

// The inbox queue keeps only the given engagements before it counts and
// cuts at the limit, so notes of engagements the user cannot see (or that
// are archived) never take a slot, and the total is the real one.
func TestBoardUnseenIn(t *testing.T) {
	d, _ := open(t)
	d.AddMembers("acme", "alice", "bob")
	d.AddMembers("gone", "alice", "bob")
	for i := 0; i < 5; i++ {
		newNote(t, d, "gone", "alice", fmt.Sprint("g", i))
	}
	for i := 0; i < 3; i++ {
		newNote(t, d, "acme", "alice", fmt.Sprint("a", i))
	}
	u, total, err := d.UnseenIn("bob", []string{"acme"}, 2)
	if err != nil || len(u) != 2 || total != 3 {
		t.Fatalf("%+v %d %v", u, total, err)
	}
	for _, n := range u {
		if n.Eng != "acme" {
			t.Fatalf("other engagement in the queue: %+v", n)
		}
	}
	// newest first
	if u[0].Num != 3 || u[1].Num != 2 {
		t.Fatalf("order %+v", u)
	}
	if u, total, err := d.UnseenIn("bob", nil, 50); err != nil || len(u) != 0 || total != 0 {
		t.Fatalf("no engagements: %+v %d %v", u, total, err)
	}
	if _, total, _ := d.UnseenIn("bob", []string{"acme", "gone"}, 50); total != 8 {
		t.Fatalf("both total %d", total)
	}
}
