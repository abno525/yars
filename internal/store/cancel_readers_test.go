package store

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/abno525/yars/internal/db"
)

// A cancel that lands between a reader seeing the finding's latest run as
// running and reading it again takes the run away: the reader then judges
// the run before it (or "never checked"), it does not fail.
func TestCancelBetweenALatestRunAndItsRead(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n")
	ref := load(t, s, fd)
	fid := ref.F.Meta.ID
	key, name := checkKey(eng, fid), eng+"/"+fid
	// a run under way that someone cancels as soon as it was read as the latest
	start := func() {
		t.Helper()
		id, err := s.DB().StartRun(eng, fid, ref.Hash, "bob", "")
		if err != nil {
			t.Fatal(err)
		}
		s.setRunning(key, id, false)
		s.beforeGateMap = func() {
			s.beforeGateMap = nil
			if gone, err := s.DB().DropRun(id); err != nil || !gone {
				t.Errorf("drop: %v %v", gone, err)
			}
			s.setRunning(key, 0, true)
		}
	}
	// never checked before
	start()
	if g, err := s.checkGate(eng, fid, ref.Hash); err != nil || g != GateNoRun {
		t.Errorf("checkGate, no run before: %q %v", g, err)
	}
	start()
	if gs, err := s.CheckGates([]GateKey{{eng, fid, ref.Hash}}); err != nil || gs[name] != GateNoRun {
		t.Errorf("CheckGates, no run before: %v %v", gs, err)
	}
	start()
	if st, err := s.CheckStatus(eng, fd); err != nil || st.HasRun || st.Running {
		t.Errorf("CheckStatus, no run before: %+v %v", st.Run, err)
	}
	// a finished run before it: that one is judged
	first, err := s.DB().StartRun(eng, fid, ref.Hash, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB().TxFor(eng, func(tx *db.Tx) error { return tx.FinishRun(first, db.RunDone, "", nil) }); err != nil {
		t.Fatal(err)
	}
	start()
	if g, err := s.checkGate(eng, fid, ref.Hash); err != nil || g != "" {
		t.Errorf("checkGate, a clean run before: %q %v", g, err)
	}
	start()
	if gs, err := s.CheckGates([]GateKey{{eng, fid, ref.Hash}}); err != nil || len(gs) != 0 {
		t.Errorf("CheckGates, a clean run before: %v %v", gs, err)
	}
	start()
	if st, err := s.CheckStatus(eng, fd); err != nil || !st.HasRun || st.Running || st.Run.ID != first || st.Run.State != db.RunDone {
		t.Errorf("CheckStatus, a clean run before: %+v %v", st.Run, err)
	}
}

// Check pressed on a finding whose run is being cancelled starts a new run:
// the run it would have joined is gone.
func TestCheckWhileItsRunIsCancelled(t *testing.T) {
	s, _, fd := newFinding(t)
	l := newCtxGate()
	s.Linter = l
	var rel sync.Once
	free := func() { rel.Do(func() { close(l.release) }) }
	t.Cleanup(free) // a failure leaves no run held
	first, err := s.StartCheck(eng, fd, uAlice)
	if err != nil {
		t.Fatal(err)
	}
	l.waitIn(t, 1)
	s.beforeJoin = func() {
		s.beforeJoin = nil
		if err := s.CancelRun(eng, fd, uAlice); err != nil {
			t.Errorf("cancel: %v", err)
		}
	}
	run, err := s.StartCheck(eng, fd, uBob)
	if err != nil {
		t.Fatalf("a check pressed while the run is cancelled: %v", err)
	}
	// the new run may bear the number of the one that went: told by who asked
	if first.By != uAlice.Username || run.By != uBob.Username {
		t.Fatalf("joined the cancelled run: %+v", run)
	}
	free()
	waitAll(t, s)
	if st, err := s.CheckStatus(eng, fd); err != nil || st.Run.ID != run.ID || st.Run.By != uBob.Username || st.Run.State != db.RunDone {
		t.Fatalf("status at the end: %+v %v", st.Run, err)
	}
}

// A check cancelled before its start has answered is answered as it was
// started, not with an error.
func TestCheckCancelledAsItStarts(t *testing.T) {
	s, _, fd := newFinding(t)
	withLimit(s, 1)
	l := newGate()
	s.Linter = l
	var rel sync.Once
	free := func() { rel.Do(func() { close(l.release) }) }
	t.Cleanup(free) // a failure leaves no run held
	fds := moreFindings(t, s, fd, 1)
	if _, err := s.StartCheck(eng, fd, uAlice); err != nil {
		t.Fatal(err)
	}
	l.waitIn(t, 1)
	other := fidOf(t, s, fds[1])
	var asked atomic.Bool // the cancel announces a change too: asked once
	// the queued run is announced inside its start: cancelled right there
	s.OnChange(func(c Change) {
		if c.Fid != other || c.Kind != ChangeCheck || !asked.CompareAndSwap(false, true) {
			return
		}
		if err := s.CancelRun(eng, fds[1], uBob); err != nil {
			t.Errorf("cancel: %v", err)
		}
	})
	run, err := s.StartCheck(eng, fds[1], uAlice)
	if err != nil || run.ID == 0 || run.By != uAlice.Username {
		t.Fatalf("a check cancelled as it starts: %+v %v", run, err)
	}
	if _, err := s.DB().Run(run.ID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("the cancelled run is stored: %v", err)
	}
	if s.CheckRunning(eng, other) {
		t.Fatal("the cancelled run is still the finding's run")
	}
	free()
	waitAll(t, s)
}
