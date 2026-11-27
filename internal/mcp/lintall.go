package mcp

import (
	"context"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/store"
)

// lintWait is how long lint_finding all=true waits for its check run: the
// time one check has for its scripts and AI questions, as the call took at
// most while it ran them itself. A run that waits in the queue can take
// longer; the answer then names the run and its state.
const lintWait = 90 * time.Second

// lintPoll is how often the wait looks at the run.
const lintPoll = 100 * time.Millisecond

// lintByCheck is lint_finding all=true on the server: every rule runs as a
// check run of the finding (Store.StartCheck: as u, in the queue's order,
// refused on an archived engagement or while a fix runs; a run already under
// way is joined), and the answer is that run's results in lint_finding's
// form, dismissed ones marked. The call waits for the run, as long as ctx and
// LintWait allow. When the run is not finished by then it lists nothing and
// says the run's state: get_check_results reads it later.
func (s *Server) lintByCheck(ctx context.Context, ref store.FindingRef, u config.User) (string, error) {
	run, err := s.Store.StartCheck(ref.EngID, ref.Dir, u)
	if err != nil {
		return "", err
	}
	wait := s.LintWait
	if wait <= 0 {
		wait = lintWait
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	tick := time.NewTicker(lintPoll)
	defer tick.Stop()
	var st store.CheckStatus
	for {
		if st, err = s.Store.CheckStatus(ref.EngID, ref.Dir); err != nil {
			return "", err
		}
		// over: this run ended, or a newer one took its place and ended
		if !st.HasRun || !st.Running {
			break
		}
		select {
		case <-ctx.Done():
		case <-tick.C:
			continue
		}
		break
	}
	type marked struct {
		rules.Violation
		Dismissed   bool   `json:"dismissed,omitempty"`
		DismissedBy string `json:"dismissed_by,omitempty"`
	}
	out := struct {
		Items   []marked `json:"items"`
		Next    string   `json:"next"`
		RunID   int64    `json:"run_id"`
		State   string   `json:"state"`
		Message string   `json:"message,omitempty"`
	}{Items: []marked{}, RunID: run.ID, State: run.State}
	if st.HasRun {
		out.RunID, out.State = st.Run.ID, st.Run.State
	}
	if st.HasRun && st.Running {
		out.Message = "the check run is " + out.State + ": nothing is listed yet; read get_check_results"
		return ok(out)
	}
	for _, x := range st.Results {
		m := marked{Violation: rules.Violation{Rule: x.Rule, Level: x.Level, Message: x.Message, Target: x.Target, Quote: x.Quote}}
		if d, ok := db.Lookup(st.Dismissed, x.Rule, x.Target, x.Quote); ok {
			m.Dismissed, m.DismissedBy = true, d.By
		}
		out.Items = append(out.Items, m)
	}
	if st.HasRun && st.Run.Error != "" {
		// a run that was cut off (the server stopped, say): its state says so
		out.Message = "the check run ended early: " + st.Run.Error
	}
	return ok(out)
}
