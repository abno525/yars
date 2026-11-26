package store

import (
	"slices"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/rules"
)

// RunQueued is the state a run waiting for a slot is reported in; it is
// stored as running (in progress, for the gate too).
const RunQueued = "queued"

// checkJob is a check run to run: run id on the finding as read when it was
// asked for (ref), one rule only or all, what a retry keeps, by whom, and
// the rules its steps were written for.
type checkJob struct {
	id        int64
	ref       FindingRef
	only      string
	keep      *carried
	by        string
	stepRules []rules.Rule
	rules     string // the rules version it was asked with (its keep is of those)
}

// checkLimit is how many check runs run at once (checks.max_running).
func (s *Store) checkLimit() int {
	if n := s.Config().Checks.MaxRunning; n > 0 {
		return n
	}
	return config.DefaultMaxRunning
}

// enqueue puts j behind the runs waiting already; false once the checks
// stopped.
func (s *Store) enqueue(j checkJob) bool {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	if s.checksStopped {
		return false
	}
	s.queue = append(s.queue, j)
	return true
}

// admit starts what fits once j is queued: j waiting is announced here, j
// starting by pumpChecks. Not queued (the checks stopped), j is dropped.
func (s *Store) admit(j checkJob, queued bool) {
	if !queued {
		s.dropCheck(j, "interrupted")
		s.checkWG.Done()
		return
	}
	s.pumpChecks()
	if s.queuedRun(j.id) {
		s.notify(Change{Eng: j.ref.EngID, Fid: j.ref.F.Meta.ID, Kind: ChangeCheck})
	}
}

// pumpChecks starts queued runs, oldest first, while a slot is free.
func (s *Store) pumpChecks() {
	limit := s.checkLimit()
	var next []checkJob
	s.queueMu.Lock()
	for !s.checksStopped && s.active < limit && len(s.queue) > 0 {
		next = append(next, s.queue[0])
		s.queue[0] = checkJob{}
		s.queue = s.queue[1:]
		s.active++
	}
	s.queueMu.Unlock()
	for _, j := range next {
		s.notify(Change{Eng: j.ref.EngID, Fid: j.ref.F.Meta.ID, Kind: ChangeCheck})
		go s.runCheck(j)
	}
}

// endCheck frees a run's slot for the next queued run.
func (s *Store) endCheck() {
	s.queueMu.Lock()
	s.active--
	s.queueMu.Unlock()
	s.pumpChecks()
}

// queuedRun reports whether run id waits for a slot.
func (s *Store) queuedRun(id int64) bool {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	return slices.ContainsFunc(s.queue, func(j checkJob) bool { return j.id == id })
}

// runNow reads run id, RunQueued while it waits for a slot.
func (s *Store) runNow(id int64) (db.CheckRun, error) {
	run, err := s.db.Run(id)
	if err == nil && run.State == db.RunRunning && s.queuedRun(id) {
		run.State = RunQueued
	}
	return run, err
}

// StopChecks drops the queued check runs (the server is stopping): each
// fails as interrupted, as a restart would leave it, and nothing more
// starts. The runs under way go on (WaitChecks).
func (s *Store) StopChecks() {
	s.queueMu.Lock()
	s.checksStopped = true
	q := s.queue
	s.queue = nil
	s.queueMu.Unlock()
	for _, j := range q {
		s.dropCheck(j, "interrupted")
		s.checkWG.Done()
	}
}

// WorkState is the background work of the store now: check runs holding a
// slot, check runs waiting for one, and fixes with AI under way.
type WorkState struct {
	ChecksRunning, ChecksQueued, Fixes int
}

// Work is the store's background work now, read from memory (no database
// call: it answers when the database does not).
func (s *Store) Work() WorkState {
	s.queueMu.Lock()
	w := WorkState{ChecksRunning: s.active, ChecksQueued: len(s.queue)}
	s.queueMu.Unlock()
	s.runningMu.Lock()
	for _, id := range s.running {
		if id == fixRun {
			w.Fixes++
		}
	}
	s.runningMu.Unlock()
	return w
}

// dropInterrupted is the reason of a run dropped at a stop.
const dropInterrupted = "interrupted"

// dropCheck ends run j without running it, failed for reason. Its log line
// says which of the two it was: interrupted (the server stops) or archived
// (the engagement closed while the run waited).
func (s *Store) dropCheck(j checkJob, reason string) {
	eng, fid := j.ref.EngID, j.ref.F.Meta.ID
	outcome := "archived"
	if reason == dropInterrupted {
		outcome = dropInterrupted
	}
	s.Log().Info("check run dropped", "eng", eng, "finding", LogID(fid), "user", j.by, "outcome", outcome)
	s.db.FailRun(j.id, reason)
	s.setRunning(checkKey(eng, fid), 0, true)
	s.notify(Change{Eng: eng, Fid: fid, Kind: ChangeCheck})
}
