package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/workflow"
)

// errCancelled is the cause of a run's context that a person cancelled
// (CancelRun), as against a server that stops.
var errCancelled = errors.New("cancelled")

// cancelWait is how long CancelRun waits for the run to end, so that its
// answer shows the finding without the run. A run that takes longer to stop
// (a script being killed) ends on its own; the page hears of it then.
const cancelWait = 2 * time.Second

// runStop is how the check or fix in progress on a finding is cancelled:
// its context, and done, closed once the run is no longer the finding's.
type runStop struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	done   chan struct{}
}

// newStop makes the context of the run that key's finding now has, under
// parent, and keeps it until setRunning forgets the run.
func (s *Store) newStop(key string, parent context.Context) *runStop {
	ctx, cancel := context.WithCancelCause(parent)
	st := &runStop{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	s.runningMu.Lock()
	if s.stops == nil {
		s.stops = map[string]*runStop{}
	}
	s.stops[key] = st
	s.runningMu.Unlock()
	return st
}

// userCancelled reports whether a person cancelled the run ctx belongs to.
func userCancelled(ctx context.Context) bool {
	return ctx != nil && errors.Is(context.Cause(ctx), errCancelled)
}

// CancelRun stops the check or the Fix with AI that runs on the finding, as
// u. It takes no run from the caller: it is the finding's own run.
//
// A check, queued or under way, leaves nothing: its run is removed, so the
// run before it is the finding's latest again (for the page, the Require
// Check gate and a retry), no result is stored, no thread is posted or
// resolved and no event is sent. A check whose results are being stored in
// the same instant is stored whole instead.
//
// A fix stops asking the AI: what it committed stays, the item it was on
// and the items it did not reach get no reply, and no check follows. Only
// someone who may edit the finding stops a fix; anyone who can start a
// check stops one. An archived engagement does not refuse: a cancel only
// stops work. With nothing running it is ErrInvalidValue.
func (s *Store) CancelRun(engID, dir string, u config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	ref, _, err := s.read(engID, dir, nil)
	if err != nil {
		return err
	}
	fid := ref.F.Meta.ID
	key := checkKey(engID, fid)
	s.checksMu.Lock()
	s.runningMu.Lock()
	id, ok := s.running[key]
	stop := s.stops[key]
	s.runningMu.Unlock()
	if !ok || stop == nil {
		s.checksMu.Unlock()
		return fmt.Errorf("%w: no check or fix of this finding is running", ErrInvalidValue)
	}
	kind := "check"
	if id == fixRun {
		kind = "fix"
		if !workflow.CanEdit(u, ref.F.Meta) {
			s.checksMu.Unlock()
			return &workflow.Denied{Reason: "this finding is " + ref.F.Meta.Status + "; " + u.Username + " cannot edit it"}
		}
	}
	s.Log().Info("cancel asked", "eng", engID, "finding", LogID(fid), "user", u.Username, "kind", kind)
	if id != fixRun {
		if j, ok := s.dequeue(id); ok {
			// it never began: nothing but its run to take away
			s.checksMu.Unlock()
			s.cancelledCheck(j)
			s.checkWG.Done()
			return nil
		}
	}
	stop.cancel(errCancelled)
	s.checksMu.Unlock()
	select {
	case <-stop.done:
	case <-time.After(cancelWait):
	}
	return nil
}

// dequeue takes run id out of the queue; false when it does not wait there.
func (s *Store) dequeue(id int64) (checkJob, bool) {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	i := slices.IndexFunc(s.queue, func(j checkJob) bool { return j.id == id })
	if i < 0 {
		return checkJob{}, false
	}
	j := s.queue[i]
	s.queue = slices.Delete(s.queue, i, i+1)
	return j, true
}

// cancelledCheck ends run j as cancelled: the run goes with its steps (no
// result was stored), so it is not a failed run for anyone who reads the
// finding's latest. No event is sent.
func (s *Store) cancelledCheck(j checkJob) {
	eng, fid := j.ref.EngID, j.ref.F.Meta.ID
	s.Log().Info("check run cancelled", "eng", eng, "finding", LogID(fid), "user", j.by)
	if _, err := s.db.DropRun(j.id); err != nil {
		s.Log().Error("check run: a cancelled run is not removed", "eng", eng, "finding", LogID(fid), "err", err)
	}
	s.setRunning(checkKey(eng, fid), 0, true)
	s.notify(Change{Eng: eng, Fid: fid, Kind: ChangeCheck})
}
