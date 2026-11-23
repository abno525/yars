package store

import "testing"

// The inbox queue takes the engagements the page shows, but keeps only those
// the user may see, whatever the caller passes.
func TestUnseenQueueVisible(t *testing.T) {
	s, _ := withEngagement(t)
	s.DB().AddMembers(eng, "alice", "bob")
	boardNote(t, s, "x", "h", "open")
	if u, n, err := s.UnseenQueue(bRev, []string{eng}, 50); err != nil || len(u) != 1 || n != 1 {
		t.Fatalf("bob %+v %d %v", u, n, err)
	}
	if u, n, _ := s.UnseenQueue(bRev, nil, 50); len(u) != 0 || n != 0 {
		t.Fatalf("no engagements %+v %d", u, n)
	}
	if err := s.RemoveMember(eng, "bob", bDir); err != nil {
		t.Fatal(err)
	}
	s.PostNote(eng, 1, "more", bPen)
	if u, n, _ := s.UnseenQueue(bRev, []string{eng, "../x"}, 50); len(u) != 0 || n != 0 {
		t.Fatalf("removed member sees %+v %d", u, n)
	}
}
