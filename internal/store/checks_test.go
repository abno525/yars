package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"yars/internal/chat"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/rules"
	"yars/internal/workflow"
)

const checkRules = `
- id: no-sql
  target: title
  regex_forbid: 'SQL'
  message: Spell out SQL
- id: no-foo
  target: section:Impact
  regex_forbid: 'foo'
  level: warning
  message: Avoid foo
`

// checked runs a check as u and waits for it to finish.
func checked(t *testing.T, s *Store, fd string) CheckStatus {
	t.Helper()
	if _, err := s.StartCheck(eng, fd, uAlice); err != nil {
		t.Fatal(err)
	}
	s.WaitChecks()
	st, err := s.CheckStatus(eng, fd)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// checkThreads returns the check threads of the finding by section.
func checkThreads(t *testing.T, s *Store, fd string) map[string]*chat.Thread {
	t.Helper()
	msgs, err := s.Chat(eng, fd)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*chat.Thread{}
	for _, it := range chat.Timeline(msgs) {
		if it.Thread != nil && it.Thread.Root.Kind == chat.KindCheck {
			if out[it.Thread.Root.Section] != nil {
				t.Fatalf("two check threads on %q", it.Thread.Root.Section)
			}
			out[it.Thread.Root.Section] = it.Thread
		}
	}
	return out
}

func TestCheckRunPostsCommentsAndProgress(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules)
	if err := s.UpdateSection(eng, fd, "Impact", "a foo here", "", alice); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var kinds []string
	s.OnChange(func(c Change) { mu.Lock(); kinds = append(kinds, c.Kind); mu.Unlock() })
	st := checked(t, s, fd)
	if !st.HasRun || st.Run.State != db.RunDone || st.Stale || st.Running || st.Run.Total != 2 || st.Run.Done != 2 || st.Run.By != "alice" {
		t.Fatalf("status %+v", st)
	}
	if len(st.Results) != 2 {
		t.Fatalf("results %+v", st.Results)
	}
	mu.Lock()
	n := strings.Count(strings.Join(kinds, ","), ChangeCheck)
	mu.Unlock()
	if n < 4 { // started, 0/2, 1/2, 2/2, finished
		t.Fatalf("check events %v", kinds)
	}
	th := checkThreads(t, s, fd)
	if len(th) != 2 || th["Impact"] == nil || th[""] == nil {
		t.Fatalf("threads %+v", th)
	}
	imp := th["Impact"].Root
	if imp.User != CheckUser || !strings.Contains(imp.Text, "Avoid foo") || !strings.Contains(imp.Text, "foo") {
		t.Fatalf("comment %+v", imp)
	}
	if st.Results[0].Thread == "" || st.Results[1].Thread == "" {
		t.Fatalf("results without thread %+v", st.Results)
	}
}

func TestCheckRunDedupesAndAutoResolves(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules)
	s.UpdateSection(eng, fd, "Impact", "a foo here", "", alice)
	checked(t, s, fd)
	first := checkThreads(t, s, fd)
	// same violations again: no new comments
	checked(t, s, fd)
	again := checkThreads(t, s, fd)
	if len(again) != 2 || again["Impact"].Root.ID != first["Impact"].Root.ID {
		t.Fatalf("duplicated: %+v", again)
	}
	// someone resolves the title thread but the title still says SQL:
	// the next run reopens it rather than posting a second one
	if _, err := s.PostChat(eng, fd, chat.Message{Resolves: first[""].Root.ID}, uAlice); err != nil {
		t.Fatal(err)
	}
	checked(t, s, fd)
	if th := checkThreads(t, s, fd); th[""].Resolved || th[""].Root.ID != first[""].Root.ID {
		t.Fatalf("title thread %+v", th[""])
	}
	// fixed in the text: the run resolves the thread, silently
	s.UpdateSection(eng, fd, "Impact", "clean now", "", alice)
	st := checked(t, s, fd)
	if len(st.Results) != 1 {
		t.Fatalf("results %+v", st.Results)
	}
	th := checkThreads(t, s, fd)
	if !th["Impact"].Resolved || th["Impact"].ResolvedBy != CheckUser || th[""].Resolved {
		t.Fatalf("after fix %+v %+v", th["Impact"], th[""])
	}
	msgs, _ := s.Chat(eng, fd)
	for _, m := range msgs {
		if m.Event != "" {
			t.Fatalf("event in chat %+v", m)
		}
	}
	// a further run changes nothing
	checked(t, s, fd)
	if msgs2, _ := s.Chat(eng, fd); len(msgs2) != len(msgs) {
		t.Fatalf("chat grew from %d to %d", len(msgs), len(msgs2))
	}
}

func TestCheckStale(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules)
	if st := checked(t, s, fd); st.Stale {
		t.Fatal("fresh run is stale")
	}
	s.UpdateSection(eng, fd, "Impact", "changed", "", alice)
	st, err := s.CheckStatus(eng, fd)
	if err != nil || !st.Stale || st.Run.State != db.RunDone {
		t.Fatalf("status %+v %v", st, err)
	}
}

func TestCheckScriptFailures(t *testing.T) {
	cases := map[string]string{
		"echo not json\n":         "invalid output",
		"echo boom >&2\nexit 3\n": "boom",
	}
	for body, want := range cases {
		s, dir, fd := ready(t)
		rd := filepath.Join(dir, ".yars", "rules")
		withRules(t, s, dir, checkRules+"- id: scr\n  script: x.sh\n")
		os.WriteFile(filepath.Join(rd, "x.sh"), []byte("#!/bin/sh\ncat >/dev/null\n"+body), 0o755)
		st := checked(t, s, fd)
		if st.Run.State != db.RunFailed || !strings.Contains(st.Run.Error, want) {
			t.Fatalf("%q: run %+v", body, st.Run)
		}
		if want == "invalid output" && st.Run.Error != "invalid output" {
			t.Fatalf("error %q", st.Run.Error)
		}
		// the violations that were found still get their comments
		if len(checkThreads(t, s, fd)) != 1 {
			t.Fatalf("%q: threads %+v", body, checkThreads(t, s, fd))
		}
	}
}

// A rule that could only report a notice (AI provider down, budget spent)
// says nothing about its earlier violations: their threads stay open.
func TestCheckNoticeKeepsThreadsOpen(t *testing.T) {
	s, _, fd := ready(t)
	fid := load(t, s, fd).F.Meta.ID
	finish := func(vs []rules.Violation) {
		t.Helper()
		id, err := s.DB().StartRun(eng, fid, "x", "alice")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB().TxForSeq(eng, func(tx *db.Tx) error { return finishCheck(tx, id, eng, fid, vs) }); err != nil {
			t.Fatal(err)
		}
	}
	finish([]rules.Violation{{Rule: "ai-r", Level: "warning", Message: "vague", Target: "section:Impact", Quote: "q"}})
	if th := checkThreads(t, s, fd); th["Impact"] == nil || th["Impact"].Resolved {
		t.Fatalf("threads %+v", th)
	}
	finish([]rules.Violation{{Rule: "ai-r", Level: "warning", Message: "AI check failed: down", Target: "ai"}})
	if th := checkThreads(t, s, fd); th["Impact"].Resolved {
		t.Fatal("an AI outage resolved the thread as fixed")
	}
}

// finisher returns a func that stores a run with the given violations on
// finding fd (as finishCheck does at the end of a run) and returns the
// chat messages that run added.
func finisher(t *testing.T, s *Store, fd string) func(vs ...rules.Violation) []chat.Message {
	fid := load(t, s, fd).F.Meta.ID
	return func(vs ...rules.Violation) []chat.Message {
		t.Helper()
		before, err := s.Chat(eng, fd)
		if err != nil {
			t.Fatal(err)
		}
		id, err := s.DB().StartRun(eng, fid, "x", "alice")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB().TxForSeq(eng, func(tx *db.Tx) error { return finishCheck(tx, id, eng, fid, vs) }); err != nil {
			t.Fatal(err)
		}
		after, err := s.Chat(eng, fd)
		if err != nil {
			t.Fatal(err)
		}
		return after[len(before):]
	}
}

var (
	vFoo = rules.Violation{Rule: "no-foo", Level: "warning", Message: "Avoid foo", Target: "section:Impact", Quote: "a foo here"}
	vSQL = rules.Violation{Rule: "no-sql", Level: "error", Message: "Spell out SQL", Target: "title", Quote: "SQL"}
)

// The same violation found again posts nothing: its open thread stands.
func TestCheckSameViolationPostsNothing(t *testing.T) {
	s, _, fd := ready(t)
	finish := finisher(t, s, fd)
	if got := finish(vFoo, vSQL); len(got) != 2 {
		t.Fatalf("first run posted %+v", got)
	}
	if got := finish(vFoo, vSQL); len(got) != 0 {
		t.Fatalf("second run posted %+v", got)
	}
	// a reworded message for the same quote is still the same violation
	again := vFoo
	again.Message = "Avoid foo, please"
	if got := finish(again, vSQL); len(got) != 0 {
		t.Fatalf("reworded run posted %+v", got)
	}
	// a new violation next to known ones posts only itself
	vBar := rules.Violation{Rule: "no-foo", Level: "warning", Message: "Avoid foo", Target: "section:Impact", Quote: "another foo"}
	if got := finish(vFoo, vSQL, vBar); len(got) != 1 || got[0].Kind != chat.KindCheck || !strings.Contains(got[0].Text, "another foo") {
		t.Fatalf("new violation posted %+v", got)
	}
	if th := checkThreadList(t, s, fd); len(th) != 3 {
		t.Fatalf("threads %d", len(th))
	}
}

// The same rule and quote in two sections are two violations, each with its
// own thread, and neither is posted again.
func TestCheckSameQuoteOtherSection(t *testing.T) {
	s, _, fd := ready(t)
	finish := finisher(t, s, fd)
	a := rules.Violation{Rule: "r", Level: "warning", Message: "m", Target: "section:Impact", Quote: "same"}
	b := a
	b.Target = "section:Description"
	if got := finish(a, b); len(got) != 2 || got[0].Section == got[1].Section {
		t.Fatalf("first run posted %+v", got)
	}
	if got := finish(a, b); len(got) != 0 {
		t.Fatalf("second run posted %+v", got)
	}
	// only the Impact one is fixed: its thread alone is resolved
	finish(b)
	th := checkThreads(t, s, fd)
	if !th["Impact"].Resolved || th["Description"].Resolved {
		t.Fatalf("threads %+v %+v", th["Impact"], th["Description"])
	}
}

// A violation no longer found has its thread resolved without any line in
// the chat (no event, no comment).
func TestCheckFixedResolvesSilently(t *testing.T) {
	s, _, fd := ready(t)
	finish := finisher(t, s, fd)
	finish(vFoo, vSQL)
	got := finish(vSQL)
	if len(got) != 1 || got[0].Resolves == "" || got[0].Text != "" || got[0].Event != "" {
		t.Fatalf("fix posted %+v", got)
	}
	th := checkThreads(t, s, fd)
	if !th["Impact"].Resolved || th["Impact"].ResolvedBy != CheckUser || th[""].Resolved {
		t.Fatalf("threads %+v %+v", th["Impact"], th[""])
	}
	msgs, _ := s.Chat(eng, fd)
	for _, m := range msgs {
		if m.Event != "" {
			t.Fatalf("event in chat %+v", m)
		}
	}
}

// A run that finds nothing posts nothing.
func TestCheckCleanRunPostsNothing(t *testing.T) {
	s, _, fd := ready(t)
	finish := finisher(t, s, fd)
	if got := finish(); len(got) != 0 {
		t.Fatalf("clean run posted %+v", got)
	}
	finish(vFoo)
	finish() // resolves silently
	if got := finish(); len(got) != 0 {
		t.Fatalf("second clean run posted %+v", got)
	}
	msgs, _ := s.Chat(eng, fd)
	items := chat.Timeline(msgs)
	if len(items) != 1 || items[0].Thread == nil || !items[0].Thread.Resolved {
		t.Fatalf("timeline %+v", items)
	}
}

// A thread a person resolved while the violation is still there is reopened,
// with no new comment or thread.
func TestCheckReopensThreadResolvedByPerson(t *testing.T) {
	s, _, fd := ready(t)
	finish := finisher(t, s, fd)
	finish(vFoo)
	root := checkThreads(t, s, fd)["Impact"].Root
	if _, err := s.PostChat(eng, fd, chat.Message{Resolves: root.ID}, uAlice); err != nil {
		t.Fatal(err)
	}
	got := finish(vFoo)
	if len(got) != 1 || got[0].Reopens != root.ID || got[0].Text != "" || got[0].Event != "" {
		t.Fatalf("reopen posted %+v", got)
	}
	th := checkThreads(t, s, fd)["Impact"]
	if th.Resolved || th.Root.ID != root.ID {
		t.Fatalf("thread %+v", th)
	}
	if got := finish(vFoo); len(got) != 0 {
		t.Fatalf("after reopen posted %+v", got)
	}
}

// A run in which a rule only produced a notice adds nothing to the chat and
// leaves that rule's threads open.
func TestCheckNoticeRunPostsNothing(t *testing.T) {
	s, _, fd := ready(t)
	finish := finisher(t, s, fd)
	finish(vFoo)
	if got := finish(rules.Violation{Rule: "no-foo", Level: "warning", Message: "AI check failed: down", Target: "ai"}); len(got) != 0 {
		t.Fatalf("notice run posted %+v", got)
	}
	if checkThreads(t, s, fd)["Impact"].Resolved {
		t.Fatal("notice resolved the thread")
	}
}

// checkThreadList returns every check thread of the finding.
func checkThreadList(t *testing.T, s *Store, fd string) []*chat.Thread {
	t.Helper()
	msgs, err := s.Chat(eng, fd)
	if err != nil {
		t.Fatal(err)
	}
	var out []*chat.Thread
	for _, it := range chat.Timeline(msgs) {
		if it.Thread != nil && it.Thread.Root.Kind == chat.KindCheck {
			out = append(out, it.Thread)
		}
	}
	return out
}

func TestCheckInterruptedRunFails(t *testing.T) {
	s, _, fd := ready(t)
	ref := load(t, s, fd)
	if _, err := s.DB().StartRun(eng, ref.F.Meta.ID, "x", "alice"); err != nil {
		t.Fatal(err)
	}
	st, err := s.CheckStatus(eng, fd)
	if err != nil || st.Running || st.Run.State != db.RunFailed || st.Run.Error != "interrupted" {
		t.Fatalf("status %+v %v", st, err)
	}
}

func TestDismissPermissions(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules)
	s.UpdateSection(eng, fd, "Impact", "a foo here", "", alice)
	checked(t, s, fd)
	// a warning: anyone with edit rights
	if err := s.Dismiss(eng, fd, "no-foo", "foo", uAlice); err != nil {
		t.Fatalf("warning by author: %v", err)
	}
	// an error: reviewers and directors only
	if err := s.Dismiss(eng, fd, "no-sql", "SQL", uAlice); !denied(err) {
		t.Fatalf("error by pentester: %v", err)
	}
	if err := s.Undismiss(eng, fd, "no-foo", "section:Impact", "foo", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Dismiss(eng, fd, "no-sql", "SQL", uBob); err != nil {
		t.Fatalf("error by reviewer: %v", err)
	}
	if err := s.Undismiss(eng, fd, "no-sql", "title", "SQL", uAlice); !denied(err) {
		t.Fatalf("undismiss error by pentester: %v", err)
	}
	if err := s.Dismiss(eng, fd, "nope", "x", uDora); err == nil {
		t.Fatal("dismissed an unknown violation")
	}
	ref := load(t, s, fd)
	ds, _ := s.Dismissals(eng, ref.F.Meta.ID)
	if d := ds[db.DismissKey("no-sql", ViolationHash("title", "SQL"))]; d.By != "bob" || d.Level != "error" {
		t.Fatalf("dismissals %+v", ds)
	}
	// dismissing closes the violation's open comment
	if th := checkThreads(t, s, fd); !th[""].Resolved || th[""].ResolvedBy != "bob" {
		t.Fatalf("title thread %+v", th[""])
	}
	// no edit rights (complete): no warning dismissals either (an open
	// warning would block the sign-off: dismissed again first)
	if err := s.Dismiss(eng, fd, "no-foo", "foo", uAlice); err != nil {
		t.Fatal(err)
	}
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Dismiss(eng, fd, "no-foo", "foo", uAlice); !denied(err) {
		t.Fatalf("warning on complete finding: %v", err)
	}
}

// slowOnly is a Linter whose one rule is a script: it finds "SECRET" in
// Impact, and only when slow rules run.
type slowOnly struct{}

func (slowOnly) Lint(_ context.Context, f *finding.Finding, kinds rules.Kind) []rules.Violation {
	if body, _ := f.Section("Impact"); kinds&rules.Slow == 0 || !strings.Contains(body, "SECRET") {
		return nil
	}
	return []rules.Violation{{Rule: "secrets", Level: "error", Message: "A secret is quoted", Target: "section:Impact", Quote: "SECRET"}}
}

// With Require Check off, Approve runs every rule, scripts too, though
// nobody pressed Check on the content: an error a script finds refuses it
// until it is dismissed.
func TestApproveRunsSlowRules(t *testing.T) {
	s, _, fd := ready(t)
	if err := s.SetRequireCheck(false, "dora"); err != nil {
		t.Fatal(err)
	}
	s.Linter = slowOnly{}
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSection(eng, fd, "Impact", "the SECRET key", "", uBob.GitAuthor()); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); !denied(err) || !strings.Contains(err.Error(), "A secret is quoted") {
		t.Fatalf("approved with a script error open: %v", err)
	}
	checked(t, s, fd)
	if err := s.DismissWhy(eng, fd, "secrets", "section:Impact", "SECRET", "a test key", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatalf("dismissed script error still blocks: %v", err)
	}
}

func TestGateIgnoresDismissed(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); !denied(err) || !strings.Contains(err.Error(), "Spell out SQL") {
		t.Fatalf("err %v", err)
	}
	// dismissable without a stored run (fast rules)
	if err := s.Dismiss(eng, fd, "no-sql", "SQL", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatalf("dismissed error still blocks: %v", err)
	}
}

// Violations without a quote (an empty section, say) are told apart by
// where they are: dismissing one leaves the others counting.
func TestDismissEmptyQuoteOnlyThatTarget(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: filled\n  check: not-empty\n  target: sections\n  message: empty\n")
	for _, sec := range []string{"Impact", "Remediation"} {
		if err := s.UpdateSection(eng, fd, sec, "", "", alice); err != nil {
			t.Fatal(err)
		}
	}
	ref := load(t, s, fd)
	var vs []rules.Violation
	for _, v := range s.Linter.Lint(context.Background(), ref.F, rules.Fast) {
		if v.Rule == "filled" {
			vs = append(vs, v)
		}
	}
	if len(vs) < 2 {
		t.Fatalf("violations %+v", vs)
	}
	if err := s.DismissWhy(eng, fd, "filled", vs[0].Target, "", "fine", uBob); err != nil {
		t.Fatal(err)
	}
	left, err := s.undismissed(eng, ref.F.Meta.ID, vs)
	if err != nil || len(left) != len(vs)-1 || left[0].Target == vs[0].Target {
		t.Fatalf("left %+v %v", left, err)
	}
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); !denied(err) {
		t.Fatalf("submit with an empty section: %v", err)
	}
	if err := s.Undismiss(eng, fd, "filled", vs[0].Target, "", uBob); err != nil {
		t.Fatal(err)
	}
	if left, _ := s.undismissed(eng, ref.F.Meta.ID, vs); len(left) != len(vs) {
		t.Fatalf("after restore %+v", left)
	}
}

// Two violations without a quote in different detail rows get a thread each.
func TestCheckEmptyQuoteThreadPerTarget(t *testing.T) {
	s, _, fd := ready(t)
	finish := finisher(t, s, fd)
	a := rules.Violation{Rule: "r", Level: "error", Message: "Host is empty", Target: "details:Host"}
	b := rules.Violation{Rule: "r", Level: "error", Message: "Port is empty", Target: "details:Port"}
	if got := finish(a, b); len(got) != 2 {
		t.Fatalf("first run posted %+v", got)
	}
	got := finish(b)
	if len(got) != 1 || got[0].Resolves == "" {
		t.Fatalf("fixing one posted %+v", got)
	}
}

// The check-finished event counts only violations that are not dismissed.
func TestCheckEventSkipsDismissed(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules)
	s.UpdateSection(eng, fd, "Impact", "a foo here", "", alice)
	checked(t, s, fd)
	if err := s.Dismiss(eng, fd, "no-sql", "SQL", uBob); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var got []Event
	s.OnEvent(func(e Event) {
		if e.Kind == EventCheck && e.State == db.RunDone {
			mu.Lock()
			got = append(got, e)
			mu.Unlock()
		}
	})
	checked(t, s, fd)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Errors != 0 || got[0].Warnings != 1 {
		t.Fatalf("events %+v", got)
	}
}

// Two starts at the same moment (two quick start_check calls) give one run.
func TestStartCheckConcurrentSameRun(t *testing.T) {
	s, dir, fd := ready(t)
	rd := filepath.Join(dir, ".yars", "rules")
	withRules(t, s, dir, "- id: slow\n  script: slow.sh\n")
	os.WriteFile(filepath.Join(rd, "slow.sh"), []byte("#!/bin/sh\ncat >/dev/null\nsleep 0.5\necho '[]'\n"), 0o755)
	ids := make([]int64, 8)
	var wg sync.WaitGroup
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			run, err := s.StartCheck(eng, fd, uAlice)
			if err != nil {
				t.Error(err)
			}
			ids[i] = run.ID
		}(i)
	}
	wg.Wait()
	s.WaitChecks()
	for _, id := range ids {
		if id != ids[0] {
			t.Fatalf("concurrent starts made several runs: %v", ids)
		}
	}
}

func TestStartCheckWhileRunningReturnsSameRun(t *testing.T) {
	s, dir, fd := ready(t)
	rd := filepath.Join(dir, ".yars", "rules")
	withRules(t, s, dir, "- id: slow\n  script: slow.sh\n")
	os.WriteFile(filepath.Join(rd, "slow.sh"), []byte("#!/bin/sh\ncat >/dev/null\nsleep 0.5\necho '[]'\n"), 0o755)
	a, err := s.StartCheck(eng, fd, uAlice)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.StartCheck(eng, fd, uBob)
	if err != nil || b.ID != a.ID {
		t.Fatalf("second start %+v %v (first %d)", b, err, a.ID)
	}
	if st, _ := s.CheckStatus(eng, fd); !st.Running {
		t.Fatal("not running")
	}
	s.WaitChecks()
	if st, _ := s.CheckStatus(eng, fd); st.Running || st.Run.State != db.RunDone {
		t.Fatalf("after wait %+v", st)
	}
}
