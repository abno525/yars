package store

import "sync"

// LockMain takes the main repo's lock; call the result to release it. Never
// take an engagement's lock while holding it (the order is engagement, then
// main).
func (s *Store) LockMain() (unlock func()) {
	s.mainMu.Lock()
	return s.mainMu.Unlock
}

// LockEngagement takes an engagement repo's lock; call the result to release
// it.
func (s *Store) LockEngagement(id string) (unlock func()) {
	l := s.engLock(id)
	l.Lock()
	return l.Unlock
}

// Git work is serialized per repository: one lock per engagement repo
// (created on first use) and one for the main repo. Lock order: an
// engagement's lock before mainMu. Database-only writes (chat,
// transitions, reviewers) take neither; SQLite serializes them.

// engLock returns the lock of an engagement's repo.
func (s *Store) engLock(id string) *sync.Mutex {
	s.locksMu.Lock()
	defer s.locksMu.Unlock()
	if s.engLocks == nil {
		s.engLocks = map[string]*sync.Mutex{}
	}
	l, ok := s.engLocks[id]
	if !ok {
		l = &sync.Mutex{}
		s.engLocks[id] = l
	}
	return l
}

// lockNew takes the locks for creating engagement id: its own repo's and
// the main repo's (which records it).
func (s *Store) lockNew(id string) (unlock func()) {
	l := s.engLock(id)
	l.Lock()
	s.mainMu.Lock()
	return func() { s.mainMu.Unlock(); l.Unlock() }
}
