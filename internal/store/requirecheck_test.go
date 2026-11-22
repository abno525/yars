package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/rules"
	"yars/internal/workflow"
)

// checkNow runs Check on the finding as u and waits for it.
func checkNow(t *testing.T, s *Store, fd string) {
	t.Helper()
	if _, err := s.StartCheck(eng, fd, uBob); err != nil {
		t.Fatal(err)
	}
	s.WaitChecks()
}

// R1: with Require Check on (the default), Sign off and Approve need a
// finished check run on the current content: none, a stale one (edited
// since), a running one and a failed one refuse, each saying so.
func TestRequireCheckGate(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n")
	if !s.RequireCheck() {
		t.Fatal("off by default")
	}
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	refused := func(act workflow.Action, u, want string) {
		t.Helper()
		err := s.Transition(eng, fd, act, "", map[string]config.User{"bob": uBob, "dora": uDora}[u])
		if !denied(err) || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s by %s: %v (want %q)", act, u, err, want)
		}
	}
	refused(workflow.Clear, "bob", GateNoRun)
	checkNow(t, s, fd)
	// edited since the run
	if err := s.UpdateSection(eng, fd, "Impact", "More.", "", uAlice); err != nil {
		t.Fatal(err)
	}
	refused(workflow.Clear, "bob", GateStale)
	// a run in progress in this server
	ref := load(t, s, fd)
	id, err := s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	s.runningMu.Lock()
	s.running[checkKey(eng, ref.F.Meta.ID)] = id
	s.runningMu.Unlock()
	refused(workflow.Clear, "bob", GateRunning)
	s.runningMu.Lock()
	delete(s.running, checkKey(eng, ref.F.Meta.ID))
	s.runningMu.Unlock()
	// left running by an earlier server: cut off by the restart
	refused(workflow.Clear, "bob", GateInterrupted)
	// failed (cut off)
	s.DB().FailRun(id, "crashed")
	refused(workflow.Clear, "bob", GateFailed)
	checkNow(t, s, fd)
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatalf("sign off after a run on this content: %v", err)
	}
	// a run after the sign-off that stored its results but failed (a script
	// rule could not run): the director's Approve waits
	ref = load(t, s, fd)
	id, _ = s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob", "")
	s.DB().TxFor(eng, func(tx *db.Tx) error { return tx.FinishRun(id, db.RunFailed, "script crashed", nil) })
	refused(workflow.Approve, "dora", GateFailed)
	checkNow(t, s, fd)
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatalf("approve after a run on this content: %v", err)
	}
}

// Q13: a check run before a rule file changed is out of date; a new run
// makes it current again.
func TestGateStaleAfterRuleChange(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n")
	checkNow(t, s, fd)
	if g, _ := s.CheckGate(eng, fd); g != "" {
		t.Fatalf("after the run: %q", g)
	}
	p := filepath.Join(dir, ".yars", "rules", "style.yaml")
	if err := os.WriteFile(p, []byte("- id: none\n  target: title\n  regex_forbid: 'qqqq'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	os.Chtimes(p, later, later)
	if g, err := s.CheckGate(eng, fd); err != nil || g != GateRules {
		t.Fatalf("after a rule change: %q %v", g, err)
	}
	if st, err := s.CheckStatus(eng, fd); err != nil || !st.Stale {
		t.Fatalf("status after a rule change: %+v %v", st, err)
	}
	// Ready to approve reads the same gate
	ref := load(t, s, fd)
	name := eng + "/" + ref.F.Meta.ID
	if gs, err := s.CheckGates([]GateKey{{Eng: eng, Fid: ref.F.Meta.ID, Hash: ref.Hash}}); err != nil || gs[name] != GateRules {
		t.Fatalf("gates after a rule change: %v %v", gs, err)
	}
	checkNow(t, s, fd)
	if g, _ := s.CheckGate(eng, fd); g != "" {
		t.Fatalf("after a new run: %q", g)
	}
	if gs, err := s.CheckGates([]GateKey{{Eng: eng, Fid: ref.F.Meta.ID, Hash: ref.Hash}}); err != nil || len(gs) != 0 {
		t.Fatalf("gates after a new run: %v %v", gs, err)
	}
}

// Q13: a Retry of one rule after the rules changed runs every rule (a page
// loaded before the change still offers Retry): the other rules' results
// came from the old rules, and a new rule never ran.
func TestRetryAfterRuleChangeRunsEveryRule(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: a\n  target: title\n  regex_forbid: 'zzz'\n")
	checkNow(t, s, fd)
	p := filepath.Join(dir, ".yars", "rules", "style.yaml")
	if err := os.WriteFile(p, []byte("- id: a\n  target: title\n  regex_forbid: 'zzz'\n- id: b\n  target: title\n  regex_forbid: 'qqqq'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	later := time.Now().Add(time.Minute)
	os.Chtimes(p, later, later)
	if _, err := s.RetryCheck(eng, fd, "a", uAlice); err != nil {
		t.Fatal(err)
	}
	s.WaitChecks()
	st, err := s.CheckStatus(eng, fd)
	if err != nil {
		t.Fatal(err)
	}
	if x := stepOf(t, st, "b"); x.State != db.StepPass {
		t.Fatalf("the new rule after a retry: %+v", x)
	}
	if g, err := s.CheckGate(eng, fd); err != nil || g != "" {
		t.Fatalf("after the retry: %q %v", g, err)
	}
}

// Q13: with the same rules the last run stays current.
func TestGateSameRulesStillCurrent(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n")
	checkNow(t, s, fd)
	s.Linter.(*rules.Engine).Rules() // a reload with nothing changed
	if g, err := s.CheckGate(eng, fd); err != nil || g != "" {
		t.Fatalf("same rules: %q %v", g, err)
	}
	// a run from before rule versions (v19) never counts as out of date
	ref := load(t, s, fd)
	id, _ := s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob", "")
	s.DB().TxFor(eng, func(tx *db.Tx) error { return tx.FinishRun(id, db.RunDone, "", nil) })
	if g, err := s.CheckGate(eng, fd); err != nil || g != "" {
		t.Fatalf("a run without a rules version: %q %v", g, err)
	}
}

// aiLinter is a linter that says whether an AI provider is set up.
type aiLinter struct{ configured bool }

func (aiLinter) Lint(context.Context, *finding.Finding, rules.Kind) []rules.Violation { return nil }
func (l aiLinter) AIConfigured() bool                                                 { return l.configured }

// Q11: with Require Check on, a run whose AI rule could not run keeps Sign
// off and Approve waiting while an AI provider is set up; without one the
// AI rules can never run, and it does not.
func TestGateAIFailedBlocksOnlyWithProvider(t *testing.T) {
	s, _, fd := ready(t)
	ref := load(t, s, fd)
	id, err := s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DB().AddSteps([]db.CheckStep{
		{RunID: id, Pos: 0, Rule: "title-word", Kind: "pattern", State: db.StepPass},
		{RunID: id, Pos: 1, Rule: "plain-words", Kind: "ai", State: db.StepFailed, Message: "AI provider timed out"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.DB().TxFor(eng, func(tx *db.Tx) error { return tx.FinishRun(id, db.RunDone, "", nil) }); err != nil {
		t.Fatal(err)
	}
	s.Linter = aiLinter{configured: true}
	if g, err := s.CheckGate(eng, fd); err != nil || g != GateAIFailed {
		t.Fatalf("with a provider: %q %v", g, err)
	}
	gates, err := s.CheckGates([]GateKey{{Eng: eng, Fid: ref.F.Meta.ID, Hash: ref.Hash}})
	if err != nil || gates[eng+"/"+ref.F.Meta.ID] != GateAIFailed {
		t.Fatalf("CheckGates with a provider: %v %v", gates, err)
	}
	s.Linter = aiLinter{configured: false}
	if g, err := s.CheckGate(eng, fd); err != nil || g != "" {
		t.Fatalf("without a provider: %q %v", g, err)
	}
}

// R1: Approve with the gate on uses the stored run, not the slow rules
// inline; off, it runs every rule as before (TestApproveRunsSlowRules).
func TestRequireCheckApproveUsesStoredRun(t *testing.T) {
	s, _, fd := ready(t)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	var slow int
	s.Linter = slowLinter{&slow}
	ref := load(t, s, fd)
	id, _ := s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob", "")
	s.DB().TxFor(eng, func(tx *db.Tx) error { return tx.FinishRun(id, db.RunDone, "", nil) })
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if slow != 0 {
		t.Fatalf("approve ran the slow rules %d times with Require Check on", slow)
	}
}

// R1: off, nothing waits for a run; the setting is audited and stays off.
func TestRequireCheckOff(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n")
	if err := s.SetRequireCheck(false, "dora"); err != nil {
		t.Fatal(err)
	}
	if s.RequireCheck() {
		t.Fatal("still on")
	}
	if v, _ := s.DB().Setting(RequireCheckKey); v != "off" {
		t.Fatalf("stored %q", v)
	}
	l, _ := s.DB().AuditLog(1)
	if len(l) != 1 || l[0].Actor != "dora" || l[0].Action != "setting.require_check" || l[0].Detail != "off" {
		t.Fatalf("audit %+v", l)
	}
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatalf("sign off with the gate off: %v", err)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatalf("approve with the gate off: %v", err)
	}
	// without rules nobody could press Check: no gate
	s2, _, fd2 := ready(t)
	if err := s2.Transition(eng, fd2, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s2.Transition(eng, fd2, workflow.Clear, "", uBob); err != nil {
		t.Fatalf("sign off without rules: %v", err)
	}
}

// The gate runs inside Sign off's write transaction, so it must not wait
// on checksMu: startCheck holds that across its own database writes, which
// wait on the transaction (each would stall until the busy timeout).
func TestCheckGateNotOnChecksMu(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n")
	ref := load(t, s, fd)
	id, err := s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob", "")
	if err != nil {
		t.Fatal(err)
	}
	s.runningMu.Lock()
	s.running = map[string]int64{checkKey(eng, ref.F.Meta.ID): id}
	s.runningMu.Unlock()
	// a start in the middle of its writes
	s.checksMu.Lock()
	defer s.checksMu.Unlock()
	got := make(chan string, 2)
	go func() {
		g, _ := s.checkGate(eng, ref.F.Meta.ID, ref.Hash)
		got <- g
		gs, _ := s.CheckGates([]GateKey{{eng, ref.F.Meta.ID, ref.Hash}})
		got <- gs[eng+"/"+ref.F.Meta.ID]
	}()
	for range 2 {
		select {
		case g := <-got:
			if g != GateRunning {
				t.Fatalf("gate %q, want %q", g, GateRunning)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("the gate waits on checksMu")
		}
	}
	// a start between its StartRun and recording the id: still running
	s.setRunning(checkKey(eng, ref.F.Meta.ID), pendingRun, false)
	if g, _ := s.checkGate(eng, ref.F.Meta.ID, ref.Hash); g != GateRunning {
		t.Fatalf("starting: %q", g)
	}
}

// A run that finishes between the gate reading it and reading the running
// map finished: it is judged as it is now, never "interrupted".
func TestCheckGateRunFinishedMeanwhile(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n")
	ref := load(t, s, fd)
	key := checkKey(eng, ref.F.Meta.ID)
	start := func() {
		id, err := s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob", "")
		if err != nil {
			t.Fatal(err)
		}
		s.setRunning(key, id, false)
		s.beforeGateMap = func() {
			s.beforeGateMap = nil
			s.DB().TxFor(eng, func(tx *db.Tx) error { return tx.FinishRun(id, db.RunDone, "", nil) })
			s.setRunning(key, 0, true)
		}
	}
	start()
	if g, err := s.checkGate(eng, ref.F.Meta.ID, ref.Hash); err != nil || g != "" {
		t.Fatalf("checkGate: %q %v", g, err)
	}
	start()
	if gs, err := s.CheckGates([]GateKey{{eng, ref.F.Meta.ID, ref.Hash}}); err != nil || len(gs) != 0 {
		t.Fatalf("CheckGates: %v %v", gs, err)
	}
	// its end marked the rules changed while it ran: the gate map reads
	// that too, not the rules it first saw
	ver := s.RulesVersion()
	id, err := s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob", ver)
	if err != nil {
		t.Fatal(err)
	}
	s.setRunning(key, id, false)
	s.beforeGateMap = func() {
		s.beforeGateMap = nil
		s.DB().TxFor(eng, func(tx *db.Tx) error { return tx.FinishRun(id, db.RunDone, "", nil) })
		s.DB().SetRunRules(id, ver+"+changed")
		s.setRunning(key, 0, true)
	}
	if gs, err := s.CheckGates([]GateKey{{eng, ref.F.Meta.ID, ref.Hash}}); err != nil || gs[eng+"/"+ref.F.Meta.ID] != GateRules {
		t.Fatalf("CheckGates after a run marked changed: %v %v", gs, err)
	}
}

// raceLinter starts a check run (as a Check pressed meanwhile) the first
// time Sign off's pre-check runs the fast rules.
type raceLinter struct {
	s    *Store
	fd   string
	done bool
}

func (l *raceLinter) Lint(_ context.Context, f *finding.Finding, _ rules.Kind) []rules.Violation {
	if !l.done {
		l.done = true
		ref, _, _ := l.s.read(eng, l.fd, nil)
		if id, err := l.s.DB().StartRun(eng, f.Meta.ID, ref.Hash, "carol", ""); err == nil {
			l.s.setRunning(checkKey(eng, f.Meta.ID), id, false)
		}
	}
	return nil
}

// A Check started between Sign off's pre-check and its change is the
// latest run inside the change: Sign off waits for it.
func TestRequireCheckRunStartedMeanwhile(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n")
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	checkNow(t, s, fd)
	s.Linter = &raceLinter{s: s, fd: fd}
	err := s.Transition(eng, fd, workflow.Clear, "", uBob)
	if !denied(err) || !strings.Contains(err.Error(), GateRunning) {
		t.Fatalf("sign off during a new run: %v", err)
	}
}

// Q10: a sign-off or an approval of a version changed since is refused as
// that (ErrConflict) before the checks: no gate refusal for content never
// read, no rule run on it.
func TestTransitionSeenBeforeChecks(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n")
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	seen := load(t, s, fd).Hash
	if err := s.UpdateSection(eng, fd, "Impact", "Changed after the read.", "", uAlice); err != nil {
		t.Fatal(err)
	}
	stale := func(act workflow.Action, u config.User) {
		t.Helper()
		if err := s.TransitionSeen(eng, fd, act, "", seen, "", u); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s of a version changed since: %v", act, err)
		}
	}
	// no check run yet: the version is what is refused
	stale(workflow.Clear, uBob)
	// off, Approve runs every rule: not on content the director never read
	if err := s.SetRequireCheck(false, "dora"); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	var slow int
	s.Linter = slowLinter{&slow}
	stale(workflow.Approve, uDora)
	if m := load(t, s, fd).F.Meta; slow != 0 || m.Status != "verification" {
		t.Fatalf("approve of a stale version ran %d slow rules; %s", slow, m.Status)
	}
}

// R1: CheckGates answers for many findings at once as checkGate does.
func TestCheckGates(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n")
	ref := load(t, s, fd)
	k := GateKey{eng, ref.F.Meta.ID, ref.Hash}
	if g, _ := s.CheckGates([]GateKey{k}); g[eng+"/"+ref.F.Meta.ID] != GateNoRun {
		t.Fatalf("no run: %v", g)
	}
	checkNow(t, s, fd)
	if g, _ := s.CheckGates([]GateKey{k}); len(g) != 0 {
		t.Fatalf("checked: %v", g)
	}
	k.Hash = "other"
	if g, _ := s.CheckGates([]GateKey{k}); g[eng+"/"+ref.F.Meta.ID] != GateStale {
		t.Fatalf("stale: %v", g)
	}
}
