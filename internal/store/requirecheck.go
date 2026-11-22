package store

import (
	"strings"

	"yars/internal/db"
)

// RequireCheckKey is the server setting (Admin) that makes Sign off and
// Approve wait for a finished check run on the finding's current content.
// Unset means on; off is stored as "off".
const RequireCheckKey = "require_check"

// Why Sign off and Approve wait while Require Check is on.
const (
	GateNoRun   = "run check first: no check run yet"
	GateStale   = "run check first: the content changed since the last check"
	GateRunning = "run check first: a check is still running"
	GateFailed  = "run check first: the last check failed"
	// Q11: an AI rule could not run although a provider is set up
	GateAIFailed = "run check first: an AI check failed; retry it"
	// Q13: the rules changed after the run
	GateRules = "run check first: the rules changed since the last check"
	// a run left running by an earlier server: a restart cut it off
	GateInterrupted = "run check first: the last check was interrupted"
)

// GateLabel is how the finding page shows any of them on the disabled
// buttons.
const GateLabel = "Run Check first"

// RequireCheck reports whether the setting is on (the default; a database
// error counts as on).
func (s *Store) RequireCheck() bool {
	if s.db == nil {
		return false
	}
	v, err := s.db.Setting(RequireCheckKey)
	return err != nil || v != "off"
}

// SetRequireCheck turns the setting on or off as actor, audited.
func (s *Store) SetRequireCheck(on bool, actor string) error {
	if s.db == nil {
		return ErrNoDB
	}
	v := "off"
	if on {
		v = "on"
	}
	if err := s.db.SetSetting(RequireCheckKey, v); err != nil {
		return err
	}
	return s.db.Audit(actor, "setting.require_check", "", v)
}

// gating reports whether the check gate applies at all: the setting is on
// and there are rules to run (without them nobody could ever press Check).
func (s *Store) gating() bool { return s.Linter != nil && s.db != nil && s.RequireCheck() }

// checkGate is why Sign off and Approve must wait for a check run on the
// finding fid of engID with content hash ("" = they need not): the latest
// run must have finished, not failed, on this content.
func (s *Store) checkGate(engID, fid, hash string) (string, error) {
	if !s.gating() {
		return "", nil
	}
	run, ok, err := s.db.LatestRun(engID, fid)
	if err != nil || !ok {
		return GateNoRun, err
	}
	if s.beforeGateMap != nil {
		s.beforeGateMap()
	}
	// called inside Sign off's transaction: runningMu only, never checksMu
	running := run.State == db.RunRunning && s.inProgress(checkKey(engID, fid), run.ID)
	if run.State == db.RunRunning && !running {
		// read again: it may have finished meanwhile (judged as it ended);
		// still running, an earlier server left it
		if run, err = s.db.Run(run.ID); err != nil {
			return "", err
		}
	}
	aiFailed, err := s.aiFailed([]int64{run.ID})
	if err != nil {
		return "", err
	}
	return gateOf(run.State, run.ContentHash, hash, running, aiFailed[run.ID], run.Rules, s.RulesVersion()), nil
}

// RulesVersion is the version of the rules in use ("" when the linter has
// none to tell).
func (s *Store) RulesVersion() string {
	if l, ok := s.Linter.(interface{ Version() string }); ok {
		return l.Version()
	}
	return ""
}

// rulesStamp tells whether the rules folder changed since: the linter's
// signature (sizes and times: a change undone moves it too), else the
// version.
func (s *Store) rulesStamp() string {
	if l, ok := s.Linter.(interface{ Stamp() string }); ok {
		return l.Stamp()
	}
	return s.RulesVersion()
}

// RulesChanged reports whether a run with the rules at version runRules is
// out of date against the rules at nowRules (both known and different).
func RulesChanged(runRules, nowRules string) bool {
	return runRules != "" && nowRules != "" && runRules != nowRules
}

// aiFailed reports which of the runs had an AI rule that could not run, while
// an AI provider is set up (Q11); without one AI rules can never run, and
// none counts.
func (s *Store) aiFailed(ids []int64) (map[int64]bool, error) {
	l, ok := s.Linter.(interface{ AIConfigured() bool })
	if !ok || !l.AIConfigured() {
		return map[int64]bool{}, nil
	}
	return s.db.FailedAIRuns(ids)
}

// gateOf decides from the latest run's state and content (running: in
// progress in this server; a run left running by an earlier server was
// cut off, so it failed; aiFailed: an AI rule of it could not run while AI is
// set up; runRules and nowRules: the rules' versions then and now).
func gateOf(state, runHash, hash string, running, aiFailed bool, runRules, nowRules string) string {
	switch {
	case state == db.RunRunning && running:
		return GateRunning
	case state == db.RunRunning:
		return GateInterrupted
	case runHash != hash:
		return GateStale
	case RulesChanged(runRules, nowRules):
		return GateRules
	case aiFailed:
		return GateAIFailed
	case state != db.RunDone:
		return GateFailed
	}
	return ""
}

// CheckGate is checkGate for the finding as it is now.
func (s *Store) CheckGate(engID, dir string) (string, error) {
	if !s.gating() {
		return "", nil
	}
	ref, raw, err := s.read(engID, dir, nil)
	if err != nil {
		return "", err
	}
	return s.checkGate(engID, ref.F.Meta.ID, contentHash(raw))
}

// GateKey names a finding for CheckGates: its engagement, id and content
// hash.
type GateKey struct{ Eng, Fid, Hash string }

// CheckGates is checkGate for many findings at once (Ready to approve), by
// "eng/fid"; findings that need not wait are left out.
func (s *Store) CheckGates(keys []GateKey) (map[string]string, error) {
	out := map[string]string{}
	if !s.gating() || len(keys) == 0 {
		return out, nil
	}
	ks := make([][2]string, len(keys))
	for i, k := range keys {
		ks[i] = [2]string{k.Eng, k.Fid}
	}
	runs, err := s.db.LatestRuns(ks)
	if err != nil {
		return nil, err
	}
	if s.beforeGateMap != nil {
		s.beforeGateMap()
	}
	// each run's state as it is now first (a run may finish meanwhile), then
	// its AI steps, so both are read after the run ended
	type judged struct {
		state, runHash, rules string
		running               bool
	}
	now := map[string]judged{}
	ids := make([]int64, 0, len(runs))
	for _, k := range keys {
		name := k.Eng + "/" + k.Fid
		r, ok := runs[name]
		if !ok {
			continue
		}
		j := judged{state: r.State, runHash: r.ContentHash, rules: r.Rules}
		j.running = j.state == db.RunRunning && s.inProgress(checkKey(k.Eng, k.Fid), r.ID)
		if j.state == db.RunRunning && !j.running {
			run, err := s.db.Run(r.ID) // finished meanwhile, or left by an earlier server
			if err != nil {
				return nil, err
			}
			j.state, j.runHash, j.rules = run.State, run.ContentHash, run.Rules // its end may mark the rules changed
		}
		now[name] = j
		ids = append(ids, r.ID)
	}
	aiFailed, err := s.aiFailed(ids) // one query for every run
	if err != nil {
		return nil, err
	}
	nowRules := s.RulesVersion()
	for _, k := range keys {
		name := k.Eng + "/" + k.Fid
		r, ok := runs[name]
		if !ok {
			out[name] = GateNoRun
			continue
		}
		j := now[name]
		if g := gateOf(j.state, j.runHash, k.Hash, j.running, aiFailed[r.ID], j.rules, nowRules); g != "" {
			out[name] = g
		}
	}
	return out, nil
}

// IsGate reports whether a refusal is the check gate's.
func IsGate(reason string) bool { return strings.Contains(reason, "run check first: ") }
