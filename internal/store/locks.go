package store

import (
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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

// defaultLockWarn is how long a wait for a repository's lock may take before
// it is logged as a warning.
const defaultLockWarn = 5 * time.Second

// repoLock is a repository's lock: a mutex that knows since when it is held
// and how many wait for it (LockStates), and logs a wait over the store's
// threshold once the lock is taken. The zero value is an unlocked lock that
// logs nothing (owner nil).
type repoLock struct {
	mu      sync.Mutex
	owner   *Store // logs the long waits; nil: none
	eng     string // "" is the main repo
	waiting atomic.Int32
	since   atomic.Int64 // when it was taken (Unix nanoseconds); 0 while free
}

// Lock takes the lock. A lock that is free costs no clock read for the wait.
func (l *repoLock) Lock() {
	if l.mu.TryLock() {
		l.since.Store(time.Now().UnixNano())
		return
	}
	start := time.Now()
	l.waiting.Add(1)
	l.mu.Lock()
	l.waiting.Add(-1)
	now := time.Now()
	l.since.Store(now.UnixNano())
	if s := l.owner; s != nil {
		if wait := now.Sub(start); wait >= s.lockWarnAfter() {
			if l.eng == "" {
				s.Log().Warn("lock: a long wait for a repository's lock", "repo", "main", "ms", wait.Milliseconds())
			} else {
				s.Log().Warn("lock: a long wait for a repository's lock", "eng", l.eng, "ms", wait.Milliseconds())
			}
		}
	}
}

// TryLock takes the lock when it is free and reports whether it did.
func (l *repoLock) TryLock() bool {
	if !l.mu.TryLock() {
		return false
	}
	l.since.Store(time.Now().UnixNano())
	return true
}

// Unlock releases the lock.
func (l *repoLock) Unlock() {
	l.since.Store(0)
	l.mu.Unlock()
}

// state is the lock as LockStates reports it; ok is false while it is free
// and nobody waits.
func (l *repoLock) state(now time.Time) (LockState, bool) {
	since, waiting := l.since.Load(), int(l.waiting.Load())
	if since == 0 && waiting == 0 {
		return LockState{}, false
	}
	st := LockState{Eng: l.eng, Waiting: waiting}
	if since != 0 {
		st.Held = max(now.Sub(time.Unix(0, since)), time.Nanosecond)
	}
	return st, true
}

// lockWarnAfter is the wait for a repository's lock that is logged.
func (s *Store) lockWarnAfter() time.Duration {
	if s.lockWarn > 0 {
		return s.lockWarn
	}
	return defaultLockWarn
}

// LockState is a repository's lock that is held or waited for: Eng is the
// engagement ("" is the main repo), Held how long it has been held (0: taken
// by nobody at the moment it was read) and Waiting how many wait for it.
type LockState struct {
	Eng     string
	Held    time.Duration
	Waiting int
}

// LockStates lists the repository locks that are held or waited for now: the
// main repo's first, then the engagements' by ID. A waiter that never gets
// its lock writes no log line, so the count here is the sign of a stuck one.
func (s *Store) LockStates() []LockState {
	now := time.Now()
	var out []LockState
	if st, ok := s.mainMu.state(now); ok {
		out = append(out, st)
	}
	s.locksMu.Lock()
	locks := make([]*repoLock, 0, len(s.engLocks))
	for _, l := range s.engLocks {
		locks = append(locks, l)
	}
	s.locksMu.Unlock()
	var engs []LockState
	for _, l := range locks {
		if st, ok := l.state(now); ok {
			engs = append(engs, st)
		}
	}
	slices.SortFunc(engs, func(a, b LockState) int { return strings.Compare(a.Eng, b.Eng) })
	return append(out, engs...)
}

// engLock returns the lock of an engagement's repo.
func (s *Store) engLock(id string) *repoLock {
	s.locksMu.Lock()
	defer s.locksMu.Unlock()
	if s.engLocks == nil {
		s.engLocks = map[string]*repoLock{}
	}
	l, ok := s.engLocks[id]
	if !ok {
		l = &repoLock{owner: s, eng: id}
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
