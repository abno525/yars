package store

// Change reports a database write confined to one finding: its engagement's
// change counter is Seq after the write. Kind is ChangeChat (only the chat
// changed) or ChangeState (workflow state, possibly with events).
type Change struct {
	Eng, Fid, Kind string
	Seq            int64
}

const (
	ChangeChat  = "chat"
	ChangeState = "state"
	// ChangeContent: a commit by YARS changed the finding's file. It does
	// not move the engagement's change counter (Seq is 0); the new HEAD
	// tells readers of the repo.
	ChangeContent = "content"
	// ChangeCheck: a check run of the finding started, progressed or ended,
	// or a violation was dismissed. Seq is 0.
	ChangeCheck = "check"
)

// OnChange registers fn to be told about every database write confined to
// one finding (chat, workflow state), after it committed.
func (s *Store) OnChange(fn func(Change)) {
	s.subsMu.Lock()
	s.subs = append(s.subs, fn)
	s.subsMu.Unlock()
}

func (s *Store) notify(c Change) {
	s.subsMu.RLock()
	subs := s.subs
	s.subsMu.RUnlock()
	for _, fn := range subs {
		fn(c)
	}
}
