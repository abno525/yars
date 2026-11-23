package store

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/workflow"
)

// In the simple workflow every account is a director; anna is the admin.
var (
	sAnna = config.User{Username: "anna", Role: "director", IsAdmin: true}
	sBen  = config.User{Username: "ben", Role: "director"}
)

func simpleConfig() config.Config {
	c := config.Default()
	c.Workflow = config.WorkflowSimple
	return c
}

// newSimpleStore is a store of the simple workflow with the test
// engagement. The workflow is given to New: the store keeps the one it was
// created with.
func newSimpleStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := gitrepo.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	s := New(r, simpleConfig(), d)
	if err := s.CreateEngagement(Engagement{ID: eng, Name: "ACME web"}, sAnna.GitAuthor()); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

// simpleDraft is a draft by anna with a severity, ready to complete.
func simpleDraft(t *testing.T) (*Store, string, string) {
	t.Helper()
	s, dir := newSimpleStore(t)
	f, err := s.CreateFinding(eng, "SQL injection", sAnna.GitAuthor())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSeverity(eng, f.Dir, "high", "", sAnna); err != nil {
		t.Fatal(err)
	}
	return s, dir, f.Dir
}

// putState stores st for the finding as a hand edit of the database would.
func putState(t *testing.T, s *Store, fd string, st db.State) {
	t.Helper()
	fid := load(t, s, fd).F.Meta.ID
	if err := s.DB().Tx(func(tx *db.Tx) error { return tx.PutState(eng, fid, st) }); err != nil {
		t.Fatal(err)
	}
}

func stateOf(t *testing.T, s *Store, fd string) db.State {
	t.Helper()
	st, err := s.DB().State(eng, load(t, s, fd).F.Meta.ID)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// Complete takes a draft to complete in one step, approved for exactly the
// content it had, with a chat event and a status event.
func TestSimpleCompleteSetsApproval(t *testing.T) {
	s, _, fd := simpleDraft(t)
	if !s.Flow().Simple {
		t.Fatal("the store does not run the simple workflow")
	}
	var evs []Event
	s.OnEvent(func(e Event) { evs = append(evs, e) })
	hash := load(t, s, fd).Hash
	if err := s.Transition(eng, fd, workflow.Complete, "", sBen); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "complete" {
		t.Fatalf("status %s", m.Status)
	}
	if st := stateOf(t, s, fd); st.Status != "complete" || st.ApprovedHash != hash {
		t.Fatalf("state %+v, hash %s", st, hash)
	}
	if got := events(t, s, fd); !reflect.DeepEqual(got, []string{"ben:complete:"}) {
		t.Fatalf("chat events %v", got)
	}
	if len(evs) != 1 || evs[0].Kind != EventStatus || evs[0].Action != "complete" || evs[0].From != "draft" || evs[0].To != "complete" ||
		evs[0].Actor != "ben" || evs[0].Author != "anna" {
		t.Fatalf("events %+v", evs)
	}
	if !SignsOff(workflow.Complete) {
		t.Fatal("complete is no sign-off action")
	}
}

// Complete needs what Approve needs, reviewers apart: a severity or a CVSS
// vector, and a retest copy's result.
func TestSimpleCompleteGate(t *testing.T) {
	s, _ := newSimpleStore(t)
	f, err := s.CreateFinding(eng, "XSS", sAnna.GitAuthor())
	if err != nil {
		t.Fatal(err)
	}
	err = s.Transition(eng, f.Dir, workflow.Complete, "", sAnna)
	if !denied(err) || err.Error() != "cannot complete: set a CVSS vector or a severity" {
		t.Fatalf("without severity: %v", err)
	}
	if err := s.UpdateSeverity(eng, f.Dir, "low", "", sAnna); err != nil {
		t.Fatal(err)
	}
	putState(t, s, f.Dir, db.State{Status: "draft", RetestSource: "old/F-001-xss"})
	if err := s.Transition(eng, f.Dir, workflow.Complete, "", sAnna); !denied(err) || !strings.Contains(err.Error(), "set the retest result") {
		t.Fatalf("retest without a result: %v", err)
	}
	if err := s.SetRetestResult(eng, f.Dir, "fixed", sAnna); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, f.Dir, workflow.Complete, "", sAnna); err != nil {
		t.Fatalf("with a result: %v", err)
	}
}

// With Require Check off, Complete runs the rules inline as Approve does:
// an error blocks it, worded as BlockingNow words it.
func TestSimpleCompleteRunsRules(t *testing.T) {
	s, dir, fd := simpleDraft(t)
	withRules(t, s, dir, "- id: t\n  target: title\n  regex_forbid: 'SQL'\n  message: no SQL in titles\n")
	if err := s.SetRequireCheck(false, "anna"); err != nil {
		t.Fatal(err)
	}
	err := s.Transition(eng, fd, workflow.Complete, "", sBen)
	if !denied(err) || err.Error() != "cannot complete: no SQL in titles" {
		t.Fatalf("err %v", err)
	}
	if why, err := s.BlockingNow(eng, fd, workflow.Complete, sBen); err != nil || why != "cannot complete: no SQL in titles" {
		t.Fatalf("BlockingNow %q %v", why, err)
	}
	if load(t, s, fd).F.Meta.Status != "draft" {
		t.Fatal("status changed")
	}
}

// Open checks block Complete, warnings too; with Require Check on and a
// rule on, Complete first waits for a check run on the content.
func TestSimpleCompleteBlockedByOpenChecks(t *testing.T) {
	s, dir, fd := simpleDraft(t)
	withRules(t, s, dir, "- id: soft\n  target: title\n  regex_forbid: 'SQL'\n  level: warning\n  message: Avoid SQL\n")
	if err := s.Transition(eng, fd, workflow.Complete, "", sBen); !denied(err) || !strings.Contains(err.Error(), GateNoRun) {
		t.Fatalf("no run: %v", err)
	}
	checkNow(t, s, fd)
	err := s.Transition(eng, fd, workflow.Complete, "", sBen)
	if !denied(err) || !strings.Contains(err.Error(), "Avoid SQL (warning)") || strings.Contains(err.Error(), "run check first") {
		t.Fatalf("open warning: %v", err)
	}
	// fixed: a new run on the new content lets it through
	if err := s.UpdateTitle(eng, fd, "Injection in search", sAnna); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Complete, "", sBen); !denied(err) || !strings.Contains(err.Error(), GateStale) {
		t.Fatalf("stale run: %v", err)
	}
	checkNow(t, s, fd)
	if err := s.Transition(eng, fd, workflow.Complete, "", sBen); err != nil {
		t.Fatalf("clean: %v", err)
	}
}

// Complete of a version the page did not show is refused as a conflict.
func TestSimpleCompleteSeen(t *testing.T) {
	s, _, fd := simpleDraft(t)
	seen := load(t, s, fd).Hash
	if err := s.UpdateSection(eng, fd, "Impact", "Changed after the read.", "", sAnna); err != nil {
		t.Fatal(err)
	}
	if err := s.TransitionSeen(eng, fd, workflow.Complete, "", seen, "", sBen); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale seen: %v", err)
	}
	if load(t, s, fd).F.Meta.Status != "draft" {
		t.Fatal("completed anyway")
	}
	if err := s.TransitionSeen(eng, fd, workflow.Complete, "", load(t, s, fd).Hash, "", sBen); err != nil {
		t.Fatalf("current seen: %v", err)
	}
}

// An edit of a complete or reported finding keeps it so: the approval moves
// to the new content.
func TestSimpleEditKeepsComplete(t *testing.T) {
	s, _, fd := simpleDraft(t)
	if err := s.Transition(eng, fd, workflow.Complete, "", sAnna); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSection(eng, fd, "Impact", "Edited once complete.", "", sBen); err != nil {
		t.Fatal(err)
	}
	ref := load(t, s, fd)
	if ref.F.Meta.Status != "complete" || stateOf(t, s, fd).ApprovedHash != ref.Hash {
		t.Fatalf("after an edit: %s, approved %s, hash %s", ref.F.Meta.Status, stateOf(t, s, fd).ApprovedHash, ref.Hash)
	}
	if err := s.Transition(eng, fd, workflow.Report, "", sBen); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSection(eng, fd, "Impact", "Edited once reported.", "", sAnna); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "reported" {
		t.Fatalf("after an edit of a reported finding: %s", m.Status)
	}
}

// A complete or reported finding whose text no longer matches its approval
// reads as draft (standard: verification), with no reviewers or sign-offs.
func TestSimpleDriftDemotesToDraft(t *testing.T) {
	s, _, fd := simpleDraft(t)
	for _, st := range []string{"complete", "reported"} {
		putState(t, s, fd, db.State{Status: st, ApprovedHash: "elsewhere", Reviewers: []db.Reviewer{{Name: "bob", ClearedHash: load(t, s, fd).Hash}}})
		m := load(t, s, fd).F.Meta
		if m.Status != "draft" || m.Reviewers != nil || m.ClearedBy != nil {
			t.Fatalf("drifted %s reads %s %v %v", st, m.Status, m.Reviewers, m.ClearedBy)
		}
		refs, err := s.ListFindings(eng)
		if err != nil || len(refs) != 1 || refs[0].F.Meta.Status != "draft" {
			t.Fatalf("listing %v", err)
		}
	}
	// it can be completed again, for the content it has now
	if err := s.Transition(eng, fd, workflow.Complete, "", sBen); err != nil {
		t.Fatal(err)
	}
	if stateOf(t, s, fd).ApprovedHash != load(t, s, fd).Hash {
		t.Fatal("not approved for the current content")
	}
	// the standard workflow reads the same state as verification
	std, _, sfd := newFinding(t)
	putState(t, std, sfd, db.State{Status: "complete", ApprovedHash: "elsewhere"})
	if m := load(t, std, sfd).F.Meta; m.Status != "verification" {
		t.Fatalf("standard drift reads %s", m.Status)
	}
}

// A stray verification status (and any stray reviewer) reads as draft with
// no reviewers: the simple workflow has neither.
func TestSimpleVerificationReadsAsDraft(t *testing.T) {
	s, _, fd := simpleDraft(t)
	hash := load(t, s, fd).Hash
	putState(t, s, fd, db.State{Status: "verification", Reviewers: []db.Reviewer{{Name: "bob", ClearedHash: hash}}})
	m := load(t, s, fd).F.Meta
	if m.Status != "draft" || m.Reviewers != nil || m.ClearedBy != nil {
		t.Fatalf("verification reads %s %v %v", m.Status, m.Reviewers, m.ClearedBy)
	}
	putState(t, s, fd, db.State{Status: "draft", Reviewers: []db.Reviewer{{Name: "bob"}}})
	if m := load(t, s, fd).F.Meta; m.Reviewers != nil {
		t.Fatalf("a draft keeps reviewers %v", m.Reviewers)
	}
	if err := s.Transition(eng, fd, workflow.Complete, "", sAnna); err != nil {
		t.Fatalf("complete it: %v", err)
	}
}

// Revert takes complete back to draft (the approval goes) and reported back
// to complete (it stays); both need a reason.
func TestSimpleRevertToDraft(t *testing.T) {
	s, _, fd := simpleDraft(t)
	if err := s.Transition(eng, fd, workflow.Complete, "", sAnna); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Reopen, " ", sBen); !denied(err) || !strings.Contains(err.Error(), "reason") {
		t.Fatalf("revert without a reason: %v", err)
	}
	if err := s.Transition(eng, fd, workflow.Reopen, "wrong host", sBen); err != nil {
		t.Fatal(err)
	}
	if st := stateOf(t, s, fd); st.Status != "draft" || st.ApprovedHash != "" {
		t.Fatalf("reverted %+v", st)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "draft" {
		t.Fatalf("reads %s", m.Status)
	}
	if err := s.Transition(eng, fd, workflow.Complete, "", sAnna); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Report, "", sAnna); err != nil {
		t.Fatal(err)
	}
	approved := stateOf(t, s, fd).ApprovedHash
	if err := s.Transition(eng, fd, workflow.Unreport, "sent too early", sBen); err != nil {
		t.Fatal(err)
	}
	if st := stateOf(t, s, fd); st.Status != "complete" || st.ApprovedHash != approved || approved == "" {
		t.Fatalf("unreported %+v", st)
	}
	want := []string{"anna:complete:", "ben:reopen:wrong host", "anna:complete:", "anna:report:", "ben:unreport:sent too early"}
	if got := events(t, s, fd); !reflect.DeepEqual(got, want) {
		t.Fatalf("events %v", got)
	}
}

// Submit, Return, Sign off, Approve and Take back are refused in every
// status, and change nothing.
func TestSimpleReviewActionsRefused(t *testing.T) {
	s, _, fd := simpleDraft(t)
	for _, st := range []string{"draft", "verification"} {
		putState(t, s, fd, db.State{Status: st})
		for _, a := range []workflow.Action{workflow.Submit, workflow.Return, workflow.Clear, workflow.Approve, workflow.TakeBack} {
			err := s.Transition(eng, fd, a, "a reason", sAnna)
			if !denied(err) || !strings.Contains(err.Error(), "is not part of the simple workflow") {
				t.Errorf("%s on %s: %v", a, st, err)
			}
		}
	}
	if st := stateOf(t, s, fd); st.Status != "verification" || len(events(t, s, fd)) != 0 {
		t.Fatalf("state %+v events %v", st, events(t, s, fd))
	}
}

// Reviewers cannot be set or added.
func TestSimpleNoReviewers(t *testing.T) {
	s, _, fd := simpleDraft(t)
	for name, err := range map[string]error{
		"set": s.SetReviewers(eng, fd, []string{"ben"}, sAnna),
		"add": s.AddReviewers(eng, fd, []string{"ben"}, sAnna),
	} {
		if !denied(err) || err.Error() != "the simple workflow has no reviewers" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if st := stateOf(t, s, fd); len(st.Reviewers) != 0 {
		t.Fatalf("reviewers stored %+v", st.Reviewers)
	}
}

// An export that marks what it sends marks a complete finding reported; a
// draft (a drifted one too) is not marked.
func TestSimpleMarkExported(t *testing.T) {
	s, _, fd := simpleDraft(t)
	if err := s.MarkExported(eng, fd, "jira", sBen); !denied(err) || !strings.Contains(err.Error(), "is draft, not complete") {
		t.Fatalf("draft: %v", err)
	}
	if err := s.Transition(eng, fd, workflow.Complete, "", sAnna); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkExported(eng, fd, "jira", sBen); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "reported" {
		t.Fatalf("status %s", m.Status)
	}
	putState(t, s, fd, db.State{Status: "complete", ApprovedHash: "elsewhere"})
	if err := s.MarkExported(eng, fd, "jira", sBen); !denied(err) || !strings.Contains(err.Error(), "is draft, not complete") {
		t.Fatalf("drifted: %v", err)
	}
}

// Withdraw (with a reason) from draft, complete or reported; Restore brings
// it back as a draft.
func TestSimpleWithdrawRestore(t *testing.T) {
	s, _, fd := simpleDraft(t)
	if err := s.Transition(eng, fd, workflow.Withdraw, "duplicate", sBen); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "withdrawn" || m.Withdrawn == nil || m.Withdrawn.By != "ben" {
		t.Fatalf("withdrawn %+v", m)
	}
	if err := s.Transition(eng, fd, workflow.Revise, "", sAnna); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "draft" {
		t.Fatalf("restored %s", m.Status)
	}
	for _, to := range []workflow.Action{workflow.Complete, workflow.Report} {
		if err := s.Transition(eng, fd, to, "", sAnna); err != nil {
			t.Fatal(err)
		}
		if err := s.Transition(eng, fd, workflow.Withdraw, "", sAnna); !denied(err) || !strings.Contains(err.Error(), "reason") {
			t.Fatalf("withdraw without a reason: %v", err)
		}
		if err := s.Transition(eng, fd, workflow.Withdraw, "out of scope", sAnna); err != nil {
			t.Fatal(err)
		}
		if st := stateOf(t, s, fd); st.Status != "withdrawn" || st.ApprovedHash != "" {
			t.Fatalf("withdrawn after %s: %+v", to, st)
		}
		if err := s.Transition(eng, fd, workflow.Revise, "", sBen); err != nil {
			t.Fatal(err)
		}
		if to == workflow.Report {
			break
		}
		if err := s.Transition(eng, fd, workflow.Complete, "", sAnna); err != nil {
			t.Fatal(err)
		}
	}
	if m := load(t, s, fd).F.Meta; m.Status != "draft" {
		t.Fatalf("end %s", m.Status)
	}
}

// The standard workflow has no Complete: refused as an unknown action, with
// rules or without, and its reviewers still change.
func TestStandardCompleteRefused(t *testing.T) {
	s, dir, fd := ready(t)
	if s.Flow().Simple {
		t.Fatal("standard store runs the simple workflow")
	}
	if err := s.Transition(eng, fd, workflow.Complete, "", uDora); !denied(err) || err.Error() != `unknown action "complete"` {
		t.Fatalf("without rules: %v", err)
	}
	withRules(t, s, dir, checkRules)
	if err := s.TransitionSeen(eng, fd, workflow.Complete, "", load(t, s, fd).Hash, "", uDora); !denied(err) || err.Error() != `unknown action "complete"` {
		t.Fatalf("with rules: %v", err)
	}
	if st := stateOf(t, s, fd); st.Status != "" && st.Status != "draft" {
		t.Fatalf("state %+v", st)
	}
	if err := s.AddReviewers(eng, fd, []string{"carol"}, uAlice); err != nil {
		t.Fatalf("standard reviewers: %v", err)
	}
}

// The store keeps the workflow it was created with: a configuration set,
// pushed or reloaded with another one keeps the rest and not that.
func TestSimpleConfigPinned(t *testing.T) {
	s, dir := newSimpleStore(t)
	var told []config.Config
	s.OnConfig(func(c config.Config) { told = append(told, c) })
	c := s.Config()
	c.Workflow, c.Sections = "", []string{"Summary", "Fix"}
	s.SetConfig(c)
	if got := s.Config(); !got.Simple() || !s.Flow().Simple || !reflect.DeepEqual(got.Sections, []string{"Summary", "Fix"}) {
		t.Fatalf("after SetConfig: %q %v", got.Workflow, got.Sections)
	}
	if len(told) != 1 || !told[0].Simple() {
		t.Fatalf("subscribers told %+v", told)
	}
	// config.yaml without the key, as a push could leave it
	if err := os.MkdirAll(filepath.Dir(config.ConfigPath(dir)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.ConfigPath(dir), []byte("sections: [A, B]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := s.ReloadConfig()
	if err != nil || !got.Simple() || !s.Config().Simple() || !reflect.DeepEqual(s.Config().Sections, []string{"A", "B"}) {
		t.Fatalf("reloaded %q %v %v", got.Workflow, s.Config().Sections, err)
	}
	// and a standard store stays standard
	std, _ := withEngagement(t)
	c = std.Config()
	c.Workflow = config.WorkflowSimple
	std.SetConfig(c)
	if std.Config().Simple() || std.Flow().Simple {
		t.Fatal("a standard store took the simple workflow")
	}
}
