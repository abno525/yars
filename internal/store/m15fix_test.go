package store

import (
	"errors"
	"testing"
	"time"
)

// Archive waits for a git write in progress (it takes the engagement lock).
func TestArchiveTakesEngLock(t *testing.T) {
	s, _, _ := newFinding(t)
	l := s.engLock(eng)
	l.Lock()
	done := make(chan error, 1)
	go func() { done <- s.Archive(eng, uDora) }()
	select {
	case err := <-done:
		l.Unlock()
		t.Fatalf("archived while a write held the lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	l.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A git write that was waiting for the lock while the engagement was
// archived is refused: the check is made under the lock.
func TestWriteRechecksArchiveUnderLock(t *testing.T) {
	s, _, fd := newFinding(t)
	l := s.engLock(eng)
	l.Lock()
	edit := make(chan error, 1)
	create := make(chan error, 1)
	go func() { edit <- s.UpdateSection(eng, fd, "Impact", "late", "", alice) }()
	go func() { _, err := s.CreateFinding(eng, "Late", alice); create <- err }()
	time.Sleep(100 * time.Millisecond) // both passed any check made before the lock
	if err := s.db.Archive(eng, "dora"); err != nil {
		l.Unlock()
		t.Fatal(err)
	}
	l.Unlock()
	if err := <-edit; !errors.Is(err, ErrArchived) {
		t.Errorf("edit after archive: %v", err)
	}
	if err := <-create; !errors.Is(err, ErrArchived) {
		t.Errorf("create after archive: %v", err)
	}
}

// Starting a check on an archived engagement is refused by the insert
// itself.
func TestStartRunArchived(t *testing.T) {
	s, _, _ := newFinding(t)
	s.db.Archive(eng, "dora")
	if _, err := s.db.StartRun(eng, "F-001", "h", "alice", ""); !errors.Is(err, ErrArchived) {
		t.Fatalf("run started on an archived engagement: %v", err)
	}
}
