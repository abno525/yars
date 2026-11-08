package store

import (
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
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
	id, err := s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob")
	if err != nil {
		t.Fatal(err)
	}
	s.checksMu.Lock()
	s.running[checkKey(eng, ref.F.Meta.ID)] = id
	s.checksMu.Unlock()
	refused(workflow.Clear, "bob", GateRunning)
	s.checksMu.Lock()
	delete(s.running, checkKey(eng, ref.F.Meta.ID))
	s.checksMu.Unlock()
	// failed (cut off)
	s.DB().FailRun(id, "crashed")
	refused(workflow.Clear, "bob", GateFailed)
	checkNow(t, s, fd)
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatalf("sign off after a run on this content: %v", err)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatalf("approve after a run on this content: %v", err)
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
	id, _ := s.DB().StartRun(eng, ref.F.Meta.ID, ref.Hash, "bob")
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
