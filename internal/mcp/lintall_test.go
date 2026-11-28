package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abno525/yars/internal/rules"
)

// withScriptRule gives f a pattern rule on the title and a script rule whose
// script notes each run in the file it returns.
func withScriptRule(t *testing.T, f *fx) (marker string) {
	t.Helper()
	rd := filepath.Join(f.dir, ".yars", "rules")
	os.MkdirAll(rd, 0o755)
	marker = filepath.Join(t.TempDir(), "ran")
	os.WriteFile(filepath.Join(rd, "r.yaml"), []byte("- id: no-sql\n  level: warning\n  target: title\n  regex_forbid: 'SQL'\n  message: Spell out SQL\n- id: scripted\n  level: warning\n  script: mark.sh\n"), 0o644)
	os.WriteFile(filepath.Join(rd, "mark.sh"), []byte("#!/bin/sh\ncat >/dev/null\necho run >> "+marker+"\necho '[{\"message\":\"script says hi\",\"target\":\"title\"}]'\n"), 0o755)
	eng := rules.NewEngine(rules.DirFor(f.dir), f.s.Cfg)
	f.s.Store.Linter, f.s.Rules = eng, eng
	return marker
}

func scriptRuns(marker string) int {
	b, _ := os.ReadFile(marker)
	return strings.Count(string(b), "run")
}

type lintAll struct {
	Items []struct {
		Rule, Level, Message, Target string
		Dismissed                    bool
	} `json:"items"`
	RunID   int64  `json:"run_id"`
	State   string `json:"state"`
	Message string `json:"message"`
}

// lint_finding all=true on the server is a check run: it is stored, as
// start_check's, the answer waits for it and lists its results, and the
// run's author is the caller.
func TestMCPLintAllIsACheckRun(t *testing.T) {
	f := newFx(t)
	marker := withScriptRule(t, f)
	a := map[string]any{"engagement": "acme", "finding": "F-001"}
	// the plain lint runs no script and stores nothing
	if out := f.ok(alice, "lint_finding", a); !strings.Contains(out, "no-sql") || strings.Contains(out, "scripted") || scriptRuns(marker) != 0 {
		t.Fatalf("plain: %s", out)
	}
	if out := f.ok(alice, "get_check_results", a); !strings.Contains(out, `"has_run":false`) {
		t.Fatalf("the plain lint stored a run: %s", out)
	}
	a["all"] = true
	var got lintAll
	out := f.ok(alice, "lint_finding", a)
	if err := json.Unmarshal([]byte(out), &got); err != nil || len(got.Items) != 2 || got.State != "done" || got.RunID == 0 || got.Message != "" {
		t.Fatalf("all=true: %s %v", out, err)
	}
	if got.Items[0].Rule != "no-sql" || got.Items[1].Rule != "scripted" || got.Items[1].Message != "script says hi" || scriptRuns(marker) != 1 {
		t.Fatalf("items %+v, %d script runs", got.Items, scriptRuns(marker))
	}
	delete(a, "all")
	var st struct {
		HasRun bool   `json:"has_run"`
		RunID  int64  `json:"run_id"`
		State  string `json:"state"`
		By     string `json:"by"`
	}
	if out := f.ok(alice, "get_check_results", a); json.Unmarshal([]byte(out), &st) != nil || !st.HasRun || st.RunID != got.RunID || st.State != "done" || st.By != "alice" {
		t.Fatalf("get_check_results: %s", out)
	}
	// a dismissed result is marked, as before
	if err := f.s.Store.DismissWhy("acme", "F-001-sql-injection", "no-sql", "title", "SQL", "fine here", bob); err != nil {
		t.Fatal(err)
	}
	a["all"] = true
	out = f.ok(alice, "lint_finding", a)
	got = lintAll{}
	if json.Unmarshal([]byte(out), &got); len(got.Items) != 2 || !got.Items[0].Dismissed || got.Items[1].Dismissed {
		t.Fatalf("after a dismissal: %s", out)
	}
}

// On an archived engagement all=true is refused as every write is, and no
// script runs; the plain lint still answers.
func TestMCPLintAllArchived(t *testing.T) {
	f := newFx(t)
	marker := withScriptRule(t, f)
	if err := f.s.Store.Archive("acme", dora); err != nil {
		t.Fatal(err)
	}
	a := map[string]any{"engagement": "acme", "finding": "F-001", "all": true}
	out, isErr := f.call(alice, "lint_finding", a)
	if !isErr || !strings.Contains(out, "archived") {
		t.Fatalf("all=true on an archived engagement: %s", out)
	}
	if scriptRuns(marker) != 0 {
		t.Fatalf("the script ran %d times", scriptRuns(marker))
	}
	delete(a, "all")
	if out := f.ok(alice, "lint_finding", a); !strings.Contains(out, "no-sql") {
		t.Fatalf("plain: %s", out)
	}
}

// all=true takes its place in the check queue: with every slot taken it
// runs nothing. When the wait is over first, the answer names the run and
// its state and lists nothing; once a slot is free the next call answers
// the results.
func TestMCPLintAllWaitsInTheQueue(t *testing.T) {
	f := newFx(t)
	withScriptRule(t, f) // s.Rules is set; the store's linter is replaced below
	l := &holdLinter{release: make(chan struct{})}
	f.s.Store.Linter = l
	c := f.s.Store.Config()
	c.Checks.MaxRunning = 1
	f.s.Store.SetConfig(c)
	released := false
	release := func() {
		if !released {
			released = true
			close(l.release)
		}
		f.s.Store.WaitChecks()
	}
	t.Cleanup(release)
	other, err := f.s.Store.CreateFinding("acme", "Reflected XSS", alice.GitAuthor())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Store.StartCheck("acme", other.Dir, alice); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(30 * time.Second); l.in.Load() != 1; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the first run did not start")
		}
	}
	f.s.LintWait = 50 * time.Millisecond
	a := map[string]any{"engagement": "acme", "finding": "F-001", "all": true}
	var got lintAll
	out := f.ok(alice, "lint_finding", a)
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.State != "queued" || got.RunID == 0 || len(got.Items) != 0 || !strings.Contains(got.Message, "get_check_results") {
		t.Fatalf("while every slot is taken: %s %v", out, err)
	}
	if l.in.Load() != 1 {
		t.Fatalf("%d runs under way with one slot", l.in.Load())
	}
	queued := got.RunID
	release()
	f.s.LintWait = time.Minute
	out = f.ok(alice, "lint_finding", a)
	got = lintAll{}
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.State != "done" || got.Message != "" {
		t.Fatalf("after the slot is free: %s %v", out, err)
	}
	if got.RunID < queued {
		t.Fatalf("run %d after the queued run %d", got.RunID, queued)
	}
}

// A run that is cancelled while all=true waits for it is said so: the call
// lists nothing and does not answer with the results of the run before it.
// get_check_results then reads that earlier run.
func TestMCPLintAllCancelled(t *testing.T) {
	f := newFx(t)
	withScriptRule(t, f)
	a := map[string]any{"engagement": "acme", "finding": "F-001", "all": true}
	var first lintAll
	if out := f.ok(alice, "lint_finding", a); json.Unmarshal([]byte(out), &first) != nil || first.State != "done" || len(first.Items) != 2 {
		t.Fatalf("the first run: %s", out)
	}
	l := &holdLinter{release: make(chan struct{})}
	f.s.Store.Linter = l
	f.s.LintWait = time.Minute
	answer := make(chan string, 1)
	go func() { answer <- f.ok(alice, "lint_finding", a) }()
	for deadline := time.Now().Add(30 * time.Second); l.in.Load() != 1; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the run did not start")
		}
	}
	if err := f.s.Store.CancelRun("acme", "F-001-sql-injection", alice); err != nil {
		t.Fatal(err)
	}
	close(l.release) // the rules return; the run ends as cancelled
	var got lintAll
	out := <-answer
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.State != "cancelled" || len(got.Items) != 0 || got.RunID <= first.RunID || !strings.Contains(got.Message, "cancelled") {
		t.Fatalf("after the cancel: %s %v", out, err)
	}
	f.s.Store.WaitChecks()
	delete(a, "all")
	var st struct {
		HasRun bool  `json:"has_run"`
		RunID  int64 `json:"run_id"`
	}
	if out := f.ok(alice, "get_check_results", a); json.Unmarshal([]byte(out), &st) != nil || !st.HasRun || st.RunID != first.RunID {
		t.Fatalf("get_check_results after the cancel: %s", out)
	}
}

// askedAI counts the questions put to the AI and finds nothing.
type askedAI struct {
	rules.SlowRunner
	n atomic.Int32
}

func (c *askedAI) AI(context.Context, rules.Rule, string, string) []rules.Violation {
	c.n.Add(1)
	return nil
}

// withAIRule gives f one AI rule on the title, asked through the counter it
// returns.
func withAIRule(t *testing.T, f *fx) *askedAI {
	t.Helper()
	rd := filepath.Join(f.dir, ".yars", "rules")
	os.MkdirAll(rd, 0o755)
	if err := os.WriteFile(filepath.Join(rd, "r.yaml"), []byte("- id: plain\n  level: warning\n  target: title\n  ai: Be plain.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	eng := rules.NewEngine(rules.DirFor(f.dir), f.s.Cfg)
	cnt := &askedAI{SlowRunner: eng.Runner}
	eng.Runner = cnt
	f.s.Store.Linter, f.s.Rules = eng, eng
	return cnt
}

// lint_finding all=true asks no AI rule where the engagement takes no AI: on
// the server (a check run) and in a clone, which reads the switch from its
// own engagement.yaml. On again, the rule is asked.
func TestMCPLintAllWhereAIIsOff(t *testing.T) {
	a := map[string]any{"engagement": "acme", "finding": "F-001", "all": true}
	lint := func(f *fx, cnt *askedAI, where string, want int32) {
		t.Helper()
		out, isErr := f.call(alice, "lint_finding", a)
		f.s.Store.WaitChecks()
		if isErr || cnt.n.Load() != want || strings.Contains(out, "plain") {
			t.Fatalf("%s: %d questions, want %d: %s", where, cnt.n.Load(), want, out)
		}
	}
	srv := newFx(t)
	cnt := withAIRule(t, srv)
	lint(srv, cnt, "the server, AI on", 1)
	if err := srv.s.Store.SetEngagementAI("acme", false, dora); err != nil {
		t.Fatal(err)
	}
	lint(srv, cnt, "the server, AI off", 1)
	if err := srv.s.Store.SetEngagementAI("acme", true, dora); err != nil {
		t.Fatal(err)
	}
	lint(srv, cnt, "the server, AI on again", 2)

	c := cloneOf(t, newFx(t))
	cnt = withAIRule(t, c)
	if c.s.Store.DB() != nil {
		t.Fatal("the clone has a database")
	}
	lint(c, cnt, "the clone, AI on", 1)
	p := filepath.Join(c.dir, "engagements", "acme", "engagement.yaml")
	on, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(strings.TrimRight(string(on), "\n")+"\nai: off\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lint(c, cnt, "the clone, AI off", 1)
	if err := os.WriteFile(p, on, 0o644); err != nil {
		t.Fatal(err)
	}
	lint(c, cnt, "the clone, AI on again", 2)
}

// yars mcp on a clone has no database, so no queue and no archive: all=true
// runs every rule inside the call, as before.
func TestMCPLintAllLocal(t *testing.T) {
	f := newFx(t)
	c := cloneOf(t, f)
	marker := withScriptRule(t, c)
	out := c.ok(alice, "lint_finding", map[string]any{"engagement": "acme", "finding": "F-001", "all": true})
	if !strings.Contains(out, "script says hi") || !strings.Contains(out, "no-sql") || scriptRuns(marker) != 1 {
		t.Fatalf("local all=true: %s (%d script runs)", out, scriptRuns(marker))
	}
}
