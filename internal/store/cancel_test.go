package store

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/workflow"
)

// ctxGate is gateLinter that also returns when its context ends, as the
// real rules do: a script is killed and an AI call is dropped. What it then
// reports is what a killed script reports: a rule that failed.
type ctxGate struct{ gateLinter }

func newCtxGate() *ctxGate { return &ctxGate{gateLinter{release: make(chan struct{})}} }

func (l *ctxGate) Lint(ctx context.Context, f *finding.Finding, k rules.Kind) []rules.Violation {
	if k != rules.All {
		return nil
	}
	l.mu.Lock()
	l.in++
	l.most = max(l.most, l.in)
	l.began = append(l.began, f.Meta.ID)
	l.mu.Unlock()
	var out []rules.Violation
	select {
	case <-l.release:
		out = l.vs
	case <-ctx.Done():
		out = []rules.Violation{{Rule: "r", Level: "error", Target: "rules", Message: "rule failed: signal: killed", Fail: "failed"}}
	}
	l.mu.Lock()
	l.in--
	l.mu.Unlock()
	return out
}

// waitBegan waits until n runs have begun.
func (l *gateLinter) waitBegan(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(l.beganNow()) != n {
		if time.Now().After(deadline) {
			t.Fatalf("%d runs began, want %d", len(l.beganNow()), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func countKind(kinds []string, k string) int {
	n := 0
	for _, x := range kinds {
		if x == k {
			n++
		}
	}
	return n
}

// A check under way can be cancelled. It leaves nothing: no run, no result,
// no thread, no event; its slot goes to the next queued run. With nothing
// running a cancel is refused with words.
func TestCancelRunningCheck(t *testing.T) {
	s, _, fd := newFinding(t)
	withLimit(s, 1)
	l := newCtxGate()
	l.vs = []rules.Violation{{Rule: "r", Level: "error", Message: "found", Target: "title", Quote: "Finding"}}
	s.Linter = l
	rec := &recorder{}
	s.OnEvent(rec.add)
	fds := moreFindings(t, s, fd, 1)
	fid := fidOf(t, s, fd)
	if err := s.CancelRun(eng, fd, uBob); !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "no check or fix of this finding is running") {
		t.Fatalf("a cancel with nothing running: %v", err)
	}
	run, err := s.StartCheck(eng, fd, uAlice)
	if err != nil {
		t.Fatal(err)
	}
	l.waitIn(t, 1)
	if next, err := s.StartCheck(eng, fds[1], uAlice); err != nil || next.State != RunQueued {
		t.Fatalf("%+v %v", next, err)
	}
	// anyone who can start a check of the finding cancels it
	if err := s.CancelRun(eng, fd, uBob); err != nil {
		t.Fatal(err)
	}
	if s.CheckRunning(eng, fid) {
		t.Fatal("the cancelled run is still the finding's run")
	}
	if _, err := s.DB().Run(run.ID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("the cancelled run is stored: %v", err)
	}
	if _, ok, err := s.DB().LatestRun(eng, fid); err != nil || ok {
		t.Fatalf("a latest run after the cancel: %v %v", ok, err)
	}
	if st, err := s.CheckStatus(eng, fd); err != nil || st.HasRun || st.Running || len(st.Results) != 0 || len(st.Steps) != 0 {
		t.Fatalf("status after the cancel: %+v %v", st, err)
	}
	if th := checkThreads(t, s, fd); len(th) != 0 {
		t.Fatalf("threads of a cancelled run: %+v", th)
	}
	// the slot is free: the queued run begins
	l.waitBegan(t, 2)
	close(l.release)
	waitAll(t, s)
	if w := s.Work(); w != (WorkState{}) {
		t.Fatalf("work after the runs ended: %+v", w)
	}
	if n := countKind(rec.kinds(), EventCheck); n != 1 {
		t.Fatalf("%d check events, want the one of the run that finished: %v", n, rec.kinds())
	}
	if st, err := s.CheckStatus(eng, fds[1]); err != nil || st.Run.State != db.RunDone || len(st.Results) != 1 {
		t.Fatalf("the run after it: %+v %v", st, err)
	}
}

// A cancelled run is no failed run for the Require Check gate: the run
// before it is the latest again, and a finding never checked reads as never
// checked.
func TestCancelledRunDoesNotHoldTheGate(t *testing.T) {
	s, _, fd := ready(t)
	l := newCtxGate()
	s.Linter = l
	close(l.release)
	first, err := s.StartCheck(eng, fd, uBob)
	if err != nil {
		t.Fatal(err)
	}
	waitAll(t, s)
	if g, err := s.CheckGate(eng, fd); err != nil || g != "" {
		t.Fatalf("after a clean run: %q %v", g, err)
	}
	l.release = make(chan struct{})
	if _, err := s.StartCheck(eng, fd, uBob); err != nil {
		t.Fatal(err)
	}
	l.waitIn(t, 1)
	if g, _ := s.CheckGate(eng, fd); g != GateRunning {
		t.Fatalf("while it runs: %q", g)
	}
	if err := s.CancelRun(eng, fd, uBob); err != nil {
		t.Fatal(err)
	}
	waitAll(t, s)
	if g, err := s.CheckGate(eng, fd); err != nil || g != "" {
		t.Fatalf("after the cancel: %q %v", g, err)
	}
	fid := fidOf(t, s, fd)
	if run, ok, err := s.DB().LatestRun(eng, fid); err != nil || !ok || run.ID != first.ID || run.State != db.RunDone {
		t.Fatalf("latest run after the cancel: %+v %v %v", run, ok, err)
	}
	gates, err := s.CheckGates([]GateKey{{Eng: eng, Fid: fid, Hash: load(t, s, fd).Full}})
	if err != nil || gates[eng+"/"+fid] != "" {
		t.Fatalf("gates after the cancel: %v %v", gates, err)
	}
	// never checked, then a cancelled check: still never checked
	other := moreFindings(t, s, fd, 1)[1]
	if _, err := s.StartCheck(eng, other, uBob); err != nil {
		t.Fatal(err)
	}
	l.waitIn(t, 1)
	if err := s.CancelRun(eng, other, uBob); err != nil {
		t.Fatal(err)
	}
	waitAll(t, s)
	if g, err := s.CheckGate(eng, other); err != nil || g != GateNoRun {
		t.Fatalf("a finding whose only check was cancelled: %q %v", g, err)
	}
}

// A queued check that is cancelled never begins; the others keep their
// order.
func TestCancelQueuedCheck(t *testing.T) {
	s, _, fd := newFinding(t)
	withLimit(s, 1)
	l := newGate()
	s.Linter = l
	fds := moreFindings(t, s, fd, 3)
	var runs []db.CheckRun
	for i, d := range fds {
		run, err := s.StartCheck(eng, d, uAlice)
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, run)
		if i == 0 {
			l.waitIn(t, 1)
		}
	}
	if err := s.CancelRun(eng, fds[2], uAlice); err != nil {
		t.Fatal(err)
	}
	if s.CheckRunning(eng, fidOf(t, s, fds[2])) {
		t.Fatal("the cancelled run is still the finding's run")
	}
	if _, err := s.DB().Run(runs[2].ID); !errors.Is(err, db.ErrNotFound) {
		t.Fatalf("the cancelled run is stored: %v", err)
	}
	if w := s.Work(); w != (WorkState{ChecksRunning: 1, ChecksQueued: 2}) {
		t.Fatalf("work after the cancel: %+v", w)
	}
	for i := range 3 {
		l.waitBegan(t, i+1)
		l.waitIn(t, 1)
		l.release <- struct{}{}
	}
	waitAll(t, s)
	want := []string{fidOf(t, s, fds[0]), fidOf(t, s, fds[1]), fidOf(t, s, fds[3])}
	if !slices.Equal(l.began, want) {
		t.Fatalf("began %v, want %v", l.began, want)
	}
	if w := s.Work(); w != (WorkState{}) {
		t.Fatalf("work at the end: %+v", w)
	}
}

// A cancel that lands after the rules ran and before their results are
// stored stores nothing: no half result.
func TestCancelBeforeFinishStoresNothing(t *testing.T) {
	s, _, fd := newFinding(t)
	l := newGate()
	l.vs = []rules.Violation{{Rule: "r", Level: "error", Message: "found", Target: "title", Quote: "Finding"}}
	close(l.release)
	s.Linter = l
	rec := &recorder{}
	s.OnEvent(rec.add)
	fid := fidOf(t, s, fd)
	s.beforeFinish = func() {
		s.runningMu.Lock()
		st := s.stops[checkKey(eng, fid)]
		s.runningMu.Unlock()
		st.cancel(errCancelled)
	}
	if _, err := s.StartCheck(eng, fd, uAlice); err != nil {
		t.Fatal(err)
	}
	waitAll(t, s)
	if st, err := s.CheckStatus(eng, fd); err != nil || st.HasRun || len(st.Results) != 0 {
		t.Fatalf("status: %+v %v", st, err)
	}
	if th := checkThreads(t, s, fd); len(th) != 0 {
		t.Fatalf("threads: %+v", th)
	}
	if n := countKind(rec.kinds(), EventCheck); n != 0 {
		t.Fatalf("%d check events for a cancelled run", n)
	}
	if s.CheckRunning(eng, fid) {
		t.Fatal("still running")
	}
}

// The next free slot goes to the account whose runs hold the fewest, then
// to the one that waited longest: one account's many checks do not keep
// another account's one check behind them. An account's own checks stay in
// the order they were asked for.
func TestCheckQueueIsFairAcrossAccounts(t *testing.T) {
	s, _, fd := newFinding(t)
	withLimit(s, 1)
	l := newGate()
	s.Linter = l
	fds := moreFindings(t, s, fd, 4)
	for i, d := range fds[:3] { // alice: one runs, two wait
		if _, err := s.StartCheck(eng, d, uAlice); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			l.waitIn(t, 1)
		}
	}
	for _, d := range fds[3:] { // bob: two, asked for last
		if run, err := s.StartCheck(eng, d, uBob); err != nil || run.State != RunQueued {
			t.Fatalf("%+v %v", run, err)
		}
	}
	for i := range fds {
		l.waitBegan(t, i+1)
		l.waitIn(t, 1)
		l.release <- struct{}{}
	}
	waitAll(t, s)
	var want []string
	for _, i := range []int{0, 3, 1, 4, 2} {
		want = append(want, fidOf(t, s, fds[i]))
	}
	if !slices.Equal(l.began, want) {
		t.Fatalf("began %v, want %v", l.began, want)
	}
}

// Fix with AI can be cancelled: nothing more is committed or asked, the item
// it was on gets no reply (and not the words of a stopping server), the busy
// mark clears and no check follows.
func TestCancelFix(t *testing.T) {
	in, hold := make(chan struct{}), make(chan struct{})
	// the provider still answers a good fix after the cancel: it is dropped
	s, dir, fd, ff := fixReady(t, "a foo here", "", func(_ rules.Violation, _, body string) (string, error) {
		close(in)
		<-hold
		return strings.ReplaceAll(body, "foo", "bar"), nil
	})
	before, fid := last(t, dir, "%H"), fidOf(t, s, fd)
	was, err := s.CheckStatus(eng, fd)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StartFix(eng, fd, uAlice); err != nil {
		t.Fatal(err)
	}
	<-in
	s.runningMu.Lock()
	stop := s.stops[checkKey(eng, fid)]
	s.runningMu.Unlock()
	if stop == nil {
		t.Fatal("a fix that cannot be cancelled")
	}
	done := make(chan error, 1)
	go func() { done <- s.CancelRun(eng, fd, uAlice) }()
	deadline := time.Now().Add(5 * time.Second)
	for !userCancelled(stop.ctx) {
		if time.Now().After(deadline) {
			t.Fatal("the cancel did not reach the fix")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(hold)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	waitAll(t, s)
	if got := aiReplies(t, s, fd); len(got) != 0 {
		t.Fatalf("replies after a cancel: %+v", got)
	}
	if last(t, dir, "%H") != before || ff.calls != 1 {
		t.Fatalf("committed, or asked again (%d calls)", ff.calls)
	}
	if s.FixRunning(eng, fid) || s.CheckRunning(eng, fid) {
		t.Fatal("the busy mark stays")
	}
	if st, err := s.CheckStatus(eng, fd); err != nil || st.Run.ID != was.Run.ID {
		t.Fatalf("a check followed the cancelled fix: %+v %v", st.Run, err)
	}
}

// Only someone who may edit the finding cancels its fix, as only they start
// one.
func TestCancelFixNeedsAnEditor(t *testing.T) {
	in, hold := make(chan struct{}), make(chan struct{})
	s, _, fd, _ := fixReady(t, "a foo here", "", func(_ rules.Violation, _, body string) (string, error) {
		close(in)
		<-hold
		return body, nil
	})
	if err := s.StartFix(eng, fd, uAlice); err != nil {
		t.Fatal(err)
	}
	<-in
	if err := s.DB().Tx(func(tx *db.Tx) error { return tx.PutState(eng, "F-001", db.State{Status: "complete"}) }); err != nil {
		t.Fatal(err)
	}
	var d *workflow.Denied
	if err := s.CancelRun(eng, fd, uAlice); !errors.As(err, &d) {
		t.Fatalf("a cancel by someone who cannot edit: %v", err)
	}
	close(hold)
	waitAll(t, s)
}
