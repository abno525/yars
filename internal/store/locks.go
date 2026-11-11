package store

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
