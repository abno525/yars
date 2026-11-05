package store

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"yars/internal/chat"
	"yars/internal/db"
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
	// fixed in the text: the run resolves the thread, with an event
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
	ev := 0
	for _, m := range msgs {
		if m.Event == EventCheckFixed && m.User == CheckUser && strings.Contains(m.Text, "no-foo") {
			ev++
		}
	}
	if ev != 1 {
		t.Fatalf("fixed events %d", ev)
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
	if err := s.Undismiss(eng, fd, "no-foo", "foo", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Dismiss(eng, fd, "no-sql", "SQL", uBob); err != nil {
		t.Fatalf("error by reviewer: %v", err)
	}
	if err := s.Undismiss(eng, fd, "no-sql", "SQL", uAlice); !denied(err) {
		t.Fatalf("undismiss error by pentester: %v", err)
	}
	if err := s.Dismiss(eng, fd, "nope", "x", uDora); err == nil {
		t.Fatal("dismissed an unknown violation")
	}
	ref := load(t, s, fd)
	ds, _ := s.Dismissals(eng, ref.F.Meta.ID)
	if d := ds[db.DismissKey("no-sql", QuoteHash("SQL"))]; d.By != "bob" || d.Level != "error" {
		t.Fatalf("dismissals %+v", ds)
	}
	// dismissing closes the violation's open comment
	if th := checkThreads(t, s, fd); !th[""].Resolved || th[""].ResolvedBy != "bob" {
		t.Fatalf("title thread %+v", th[""])
	}
	// no edit rights (complete): no warning dismissals either
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Dismiss(eng, fd, "no-foo", "foo", uAlice); !denied(err) {
		t.Fatalf("warning on complete finding: %v", err)
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
