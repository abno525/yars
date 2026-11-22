package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/rules"
)

// gateLinter holds each check run (every rule kind) until a token comes on
// release; it keeps the findings whose runs began, in order, and how many
// ran at once at most.
type gateLinter struct {
	release  chan struct{}
	mu       sync.Mutex
	in, most int
	began    []string
}

func newGate() *gateLinter { return &gateLinter{release: make(chan struct{})} }

func (l *gateLinter) Lint(_ context.Context, f *finding.Finding, k rules.Kind) []rules.Violation {
	if k != rules.All {
		return nil // the fast rules for pages and gates
	}
	l.mu.Lock()
	l.in++
	l.most = max(l.most, l.in)
	l.began = append(l.began, f.Meta.ID)
	l.mu.Unlock()
	<-l.release
	l.mu.Lock()
	l.in--
	l.mu.Unlock()
	return nil
}

func (l *gateLinter) inside() int { l.mu.Lock(); defer l.mu.Unlock(); return l.in }

// waitIn waits until n runs are inside the rules.
func (l *gateLinter) waitIn(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for l.inside() != n {
		if time.Now().After(deadline) {
			t.Fatalf("%d runs inside the rules, want %d", l.inside(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// withLimit sets checks.max_running.
func withLimit(s *Store, n int) {
	c := s.Config()
	c.Checks.MaxRunning = n
	s.SetConfig(c)
}

// moreFindings adds n findings to the test engagement and returns their
// folders, the first finding's first.
func moreFindings(t *testing.T, s *Store, first string, n int) []string {
	t.Helper()
	out := []string{first}
	for i := range n {
		f, err := s.CreateFinding(eng, fmt.Sprint("Finding ", i), alice)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f.Dir)
	}
	return out
}

// waitAll is WaitChecks with a time limit: a queued run must never leave
// it hanging.
func waitAll(t *testing.T, s *Store) {
	t.Helper()
	done := make(chan struct{})
	go func() { s.WaitChecks(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("WaitChecks hangs")
	}
}

func fidOf(t *testing.T, s *Store, fd string) string { t.Helper(); return load(t, s, fd).F.Meta.ID }

// Q3: many starts at once never run more than checks.max_running together;
// the others wait, each as its finding's one run, and all of them end.
func TestCheckLimitHoldsUnderParallelStarts(t *testing.T) {
	s, _, fd := newFinding(t)
	withLimit(s, 2)
	l := newGate()
	s.Linter = l
	fds := moreFindings(t, s, fd, 7)
	ids := make([][2]int64, len(fds))
	var wg sync.WaitGroup
	for i, d := range fds {
		for k := range 2 { // two starts of each finding
			wg.Add(1)
			go func() {
				defer wg.Done()
				run, err := s.StartCheck(eng, d, uAlice)
				if err != nil {
					t.Error(err)
				}
				ids[i][k] = run.ID
			}()
		}
	}
	wg.Wait()
	l.waitIn(t, 2)
	queued, running := 0, 0
	for i, d := range fds {
		if ids[i][0] != ids[i][1] || ids[i][0] == 0 {
			t.Fatalf("two starts of %s: runs %v", d, ids[i])
		}
		st, err := s.CheckStatus(eng, d)
		if err != nil || !st.Running {
			t.Fatalf("%s: %+v %v", d, st, err)
		}
		if st.Queued {
			queued++
			if st.Run.State != RunQueued {
				t.Fatalf("queued run's state %q", st.Run.State)
			}
		} else {
			running++
		}
	}
	if queued != 6 || running != 2 {
		t.Fatalf("%d queued, %d running", queued, running)
	}
	close(l.release)
	waitAll(t, s)
	if l.most != 2 || len(l.began) != 8 {
		t.Fatalf("at most %d at once, %d ran", l.most, len(l.began))
	}
	for i := range fds {
		if r, err := s.DB().Run(ids[i][0]); err != nil || r.State != db.RunDone {
			t.Fatalf("run %d: %+v %v", ids[i][0], r, err)
		}
	}
}

// Q3: queued runs start in the order they were asked for, each when a slot
// frees; a second start of a queued finding answers its run, queued.
func TestCheckQueueFirstInFirstOut(t *testing.T) {
	s, _, fd := newFinding(t)
	withLimit(s, 1)
	l := newGate()
	s.Linter = l
	fds := moreFindings(t, s, fd, 3)
	first, err := s.StartCheck(eng, fds[0], uAlice)
	if err != nil || first.State != db.RunRunning {
		t.Fatalf("first: %+v %v", first, err)
	}
	l.waitIn(t, 1)
	for _, d := range fds[1:] {
		run, err := s.StartCheck(eng, d, uAlice)
		if err != nil || run.State != RunQueued {
			t.Fatalf("%s: %+v %v", d, run, err)
		}
		again, err := s.StartCheck(eng, d, uBob)
		if err != nil || again.ID != run.ID || again.State != RunQueued {
			t.Fatalf("again %s: %+v %v (first %d)", d, again, err, run.ID)
		}
	}
	for i := range fds {
		l.waitIn(t, 1)
		l.release <- struct{}{}
		if i+1 < len(fds) {
			// the next one starts once the slot is free
			deadline := time.Now().Add(5 * time.Second)
			for len(l.beganNow()) != i+2 {
				if time.Now().After(deadline) {
					t.Fatalf("run %d did not start", i+2)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}
	}
	waitAll(t, s)
	var want []string
	for _, d := range fds {
		want = append(want, fidOf(t, s, d))
	}
	if !slices.Equal(l.began, want) || l.most != 1 {
		t.Fatalf("began %v (want %v), at most %d at once", l.began, want, l.most)
	}
}

func (l *gateLinter) beganNow() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.began)
}

// Q3: a queued run is the finding's run in progress: the gate waits for
// it, and it is in progress for Fix with AI's check too.
func TestQueuedRunCountsAsRunning(t *testing.T) {
	s, _, fd := ready(t)
	withLimit(s, 1)
	l := newGate()
	s.Linter = l
	fds := moreFindings(t, s, fd, 1)
	if _, err := s.StartCheck(eng, fds[1], uAlice); err != nil {
		t.Fatal(err)
	}
	l.waitIn(t, 1)
	run, err := s.StartCheck(eng, fd, uAlice)
	if err != nil || run.State != RunQueued {
		t.Fatalf("%+v %v", run, err)
	}
	if !s.CheckRunning(eng, fidOf(t, s, fd)) {
		t.Fatal("a queued run is not in progress")
	}
	if g, err := s.CheckGate(eng, fd); err != nil || g != GateRunning {
		t.Fatalf("gate %q %v", g, err)
	}
	close(l.release)
	waitAll(t, s)
	if st, err := s.CheckStatus(eng, fd); err != nil || st.Running || st.Queued || st.Run.State != db.RunDone {
		t.Fatalf("after %+v %v", st, err)
	}
}

// Q3: a raised limit starts queued runs at once.
func TestRaisedLimitStartsQueuedRuns(t *testing.T) {
	s, _, fd := newFinding(t)
	withLimit(s, 1)
	l := newGate()
	s.Linter = l
	fds := moreFindings(t, s, fd, 1)
	for _, d := range fds {
		if _, err := s.StartCheck(eng, d, uAlice); err != nil {
			t.Fatal(err)
		}
	}
	l.waitIn(t, 1)
	withLimit(s, 2)
	l.waitIn(t, 2)
	close(l.release)
	waitAll(t, s)
}

// Q3: a stopping server drops the queued runs (failed as interrupted, as a
// restart would leave them) and waits only for the runs under way; a start
// after the stop does not wait either.
func TestStopChecksDropsQueuedRuns(t *testing.T) {
	s, _, fd := newFinding(t)
	withLimit(s, 1)
	l := newGate()
	s.Linter = l
	fds := moreFindings(t, s, fd, 2)
	a, _ := s.StartCheck(eng, fds[0], uAlice)
	l.waitIn(t, 1)
	b, err := s.StartCheck(eng, fds[1], uAlice)
	if err != nil || b.State != RunQueued {
		t.Fatalf("%+v %v", b, err)
	}
	s.StopChecks()
	if r, _ := s.DB().Run(b.ID); r.State != db.RunFailed || r.Error != "interrupted" {
		t.Fatalf("dropped run %+v", r)
	}
	if s.CheckRunning(eng, fidOf(t, s, fds[1])) {
		t.Fatal("a dropped run is still the finding's run")
	}
	c, err := s.StartCheck(eng, fds[2], uAlice)
	if err != nil || c.State != db.RunFailed {
		t.Fatalf("start after the stop: %+v %v", c, err)
	}
	close(l.release)
	waitAll(t, s)
	if r, _ := s.DB().Run(a.ID); r.State != db.RunDone {
		t.Fatalf("the run under way %+v", r)
	}
	if len(l.began) != 1 {
		t.Fatalf("began %v", l.began)
	}
}

// Q3: a queued run checks the finding as it was when asked for, as a run
// under way does: edited meanwhile it ends stale, removed meanwhile it
// still ends with its results.
func TestQueuedRunOfChangedFinding(t *testing.T) {
	s, dir, fd := newFinding(t)
	withLimit(s, 1)
	l := newGate()
	s.Linter = l
	fds := moreFindings(t, s, fd, 2)
	s.StartCheck(eng, fds[0], uAlice)
	l.waitIn(t, 1)
	changed, _ := s.StartCheck(eng, fds[1], uAlice)
	gone, _ := s.StartCheck(eng, fds[2], uAlice)
	if changed.State != RunQueued || gone.State != RunQueued {
		t.Fatalf("%+v %+v", changed, gone)
	}
	if err := s.UpdateSection(eng, fds[1], "Impact", "edited while queued", "", alice); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(dir, "engagements", eng, "findings", fds[2])); err != nil {
		t.Fatal(err)
	}
	close(l.release)
	waitAll(t, s)
	st, err := s.CheckStatus(eng, fds[1])
	if err != nil || st.Run.ID != changed.ID || st.Run.State != db.RunDone || !st.Stale {
		t.Fatalf("edited: %+v %v", st, err)
	}
	if r, err := s.DB().Run(gone.ID); err != nil || r.State != db.RunDone {
		t.Fatalf("removed: %+v %v", r, err)
	}
}
