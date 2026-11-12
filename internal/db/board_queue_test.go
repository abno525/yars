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

// Mark all read sees what the queue lists, up to each note's newest entry,
// of the given engagements only; a director off the team gets no seen row
// for a note they never opened (one would make them follow it).
func TestSeeUnseenIn(t *testing.T) {
	d, _ := open(t)
	d.AddMembers("acme", "alice", "bob")
	d.AddMembers("gone", "alice", "bob")
	newNote(t, d, "acme", "alice", "a1")
	newNote(t, d, "acme", "alice", "a2")
	newNote(t, d, "gone", "alice", "g1")
	if err := d.SeeUnseenIn("bob", []string{"acme"}); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := d.UnseenIn("bob", []string{"acme"}, 50); total != 0 {
		t.Fatalf("acme still unseen: %d", total)
	}
	if _, total, _ := d.UnseenIn("bob", []string{"gone"}, 50); total != 1 {
		t.Fatalf("another engagement marked: %d", total)
	}
	d.PostNote("acme", 1, "alice", "again")
	if u, _, _ := d.UnseenIn("bob", []string{"acme"}, 50); len(u) != 1 || u[0].LastText != "again" {
		t.Fatalf("a new entry: %+v", u)
	}
	// dora sees acme without being on its team: she follows note 1 only
	d.SeeNote("dora", "acme", 1)
	d.PostNote("acme", 1, "alice", "for dora")
	if err := d.SeeUnseenIn("dora", []string{"acme"}); err != nil {
		t.Fatal(err)
	}
	var n int
	d.QueryRow("SELECT count(*) FROM board_seen WHERE username = 'dora' AND eng = 'acme' AND num = 2").Scan(&n)
	if n != 0 {
		t.Fatal("dora follows a note she never opened")
	}
	if _, total, _ := d.UnseenIn("dora", []string{"acme"}, 50); total != 0 {
		t.Fatalf("dora's note still unseen: %d", total)
	}
}
