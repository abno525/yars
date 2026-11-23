package store

import (
	"errors"
	"testing"
)

// Starting a check on an archived engagement is refused by the insert
// itself.
func TestStartRunArchived(t *testing.T) {
	s, _, _ := newFinding(t)
	s.db.Archive(eng, "dora")
	if _, err := s.db.StartRun(eng, "F-001", "h", "alice", ""); !errors.Is(err, ErrArchived) {
		t.Fatalf("run started on an archived engagement: %v", err)
	}
}
