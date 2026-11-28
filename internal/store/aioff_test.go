package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/workflow"
)

// countAI counts the questions put to the AI and finds nothing; scripts run
// as the engine's own runner runs them.
type countAI struct {
	rules.SlowRunner
	mu sync.Mutex
	n  int
}

func (c *countAI) AI(context.Context, rules.Rule, string, string) []rules.Violation {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return nil
}

func (c *countAI) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

const aiOffRules = "- id: ai\n  level: warning\n  target: title\n  ai: Be plain.\n- id: re\n  target: title\n  regex_forbid: 'zzz'\n"

// engFile is the engagement.yaml of the test engagement as it is on disk.
func engFile(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "engagements", eng, "engagement.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A client that allows no AI: with the engagement's switch off no AI rule is
// asked on any path (Check, Retry, a check of many, a lint of posted content,
// a lint of the finding as read, Sign off and Approve with Require Check
// off), the AI rule is no step of the check and leaves no notice, and the
// other rules run. Another engagement is still asked, and so is this one
// once the switch is on again. A director flips it: one commit and one audit
// row.
func TestEngagementAIOff(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, aiOffRules)
	e := s.Linter.(*rules.Engine)
	cnt := &countAI{SlowRunner: e.Runner}
	e.Runner = cnt
	checkNow(t, s, fd)
	st, err := s.CheckStatus(eng, fd)
	if err != nil || cnt.calls() != 1 || st.Run.Total != 2 || stepOf(t, st, "ai").Kind != "ai" {
		t.Fatalf("AI on: %d calls, run %+v, steps %+v, %v", cnt.calls(), st.Run, st.Steps, err)
	}

	for _, u := range []struct {
		name string
		err  error
	}{{"alice", s.SetEngagementAI(eng, false, uAlice)}, {"bob", s.SetEngagementAI(eng, false, uBob)}} {
		if !denied(u.err) {
			t.Fatalf("%s switched it off: %v", u.name, u.err)
		}
	}
	if strings.Contains(engFile(t, dir), "ai:") {
		t.Fatalf("switched off by a non-director:\n%s", engFile(t, dir))
	}
	if err := s.SetEngagementAI(eng, false, uDora); err != nil {
		t.Fatal(err)
	}
	if got := engFile(t, dir); !strings.Contains(got, "ai: \"off\"\n") || !strings.Contains(got, "name: ACME web\n") {
		t.Fatalf("engagement.yaml:\n%s", got)
	}
	if got := last(t, dir, "%an|%s"); got != "dora|engagement "+eng+": AI off" {
		t.Fatalf("commit %q", got)
	}
	if l, _ := s.DB().AuditLog(1); len(l) != 1 || l[0].Actor != "dora" || l[0].Action != "eng.ai" || l[0].Target != eng || l[0].Detail != "off" {
		t.Fatalf("audit %+v", l)
	}
	// the same switch again is no commit
	head := last(t, dir, "%H")
	if err := s.SetEngagementAI(eng, false, uDora); err != nil || last(t, dir, "%H") != head {
		t.Fatalf("a second off: %v, commit %s", err, last(t, dir, "%s"))
	}
	if e, err := s.Engagement(eng); err != nil || !e.AIOff() {
		t.Fatalf("engagement %+v %v", e, err)
	}
	if m := load(t, s, fd).F.Meta; !m.NoAI || m.Engagement != eng {
		t.Fatalf("the finding as read: %+v", m)
	}

	none := func(path string) {
		t.Helper()
		if cnt.calls() != 1 {
			t.Fatalf("%s: the AI was asked (%d calls)", path, cnt.calls())
		}
	}
	checkNow(t, s, fd)
	none("Check")
	st, err = s.CheckStatus(eng, fd)
	if err != nil || st.Run.Total != 1 || st.Run.Done != 1 || len(st.Steps) != 1 || st.Steps[0].Rule != "re" || len(st.Results) != 0 {
		t.Fatalf("the check where AI is off: run %+v, steps %+v, results %+v, %v", st.Run, st.Steps, st.Results, err)
	}
	if _, err := s.RetryCheck(eng, fd, "ai", uBob); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("a retry of the AI rule: %v", err)
	}
	s.WaitChecks()
	none("Retry")
	if _, err := s.StartCheckOfMany(eng, fd, uBob); err != nil {
		t.Fatal(err)
	}
	s.WaitChecks()
	none("a check of many")
	ref := load(t, s, fd)
	if vs, err := s.LintContent(context.Background(), eng, ref.F.Bytes(), rules.All); err != nil || len(vs) != 0 {
		t.Fatalf("lint of posted content: %+v %v", vs, err)
	}
	none("a lint of posted content")
	if vs := s.Linter.Lint(context.Background(), ref.F, rules.All); len(vs) != 0 {
		t.Fatalf("lint of the finding as read: %+v", vs)
	}
	none("a lint of the finding as read")
	// with Require Check off, Approve runs every rule in the request
	if err := s.SetRequireCheck(false, "dora"); err != nil {
		t.Fatal(err)
	}
	for _, step := range []struct {
		act workflow.Action
		err error
	}{{workflow.Submit, s.Transition(eng, fd, workflow.Submit, "", uAlice)}, {workflow.Clear, s.Transition(eng, fd, workflow.Clear, "", uBob)},
		{workflow.Approve, s.Transition(eng, fd, workflow.Approve, "", uDora)}} {
		if step.err != nil {
			t.Fatalf("%s: %v", step.act, step.err)
		}
	}
	none("Submit, Sign off and Approve")

	// another engagement, the same rules: asked
	if err := s.CreateEngagement(Engagement{ID: "beta", Name: "Beta", Type: "pentest"}, alice); err != nil {
		t.Fatal(err)
	}
	f, err := s.CreateFinding("beta", "SQLi", alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.StartCheck("beta", f.Dir, uBob); err != nil {
		t.Fatal(err)
	}
	s.WaitChecks()
	if cnt.calls() != 2 {
		t.Fatalf("another engagement: %d calls", cnt.calls())
	}
	// on again: the key goes, the rule is a step again
	if err := s.SetEngagementAI(eng, true, uDora); err != nil {
		t.Fatal(err)
	}
	if got := engFile(t, dir); strings.Contains(got, "ai:") {
		t.Fatalf("engagement.yaml after on:\n%s", got)
	}
	if l, _ := s.DB().AuditLog(1); len(l) != 1 || l[0].Action != "eng.ai" || l[0].Detail != "on" {
		t.Fatalf("audit %+v", l)
	}
	checkNow(t, s, fd)
	if st, err = s.CheckStatus(eng, fd); err != nil || cnt.calls() != 3 || st.Run.Total != 2 {
		t.Fatalf("on again: %d calls, run %+v, %v", cnt.calls(), st.Run, err)
	}
	if err := s.Archive(eng, m17Dir); err != nil {
		t.Fatal(err)
	}
	if err := s.SetEngagementAI(eng, false, uDora); !errors.Is(err, ErrArchived) {
		t.Fatalf("an archived engagement: %v", err)
	}
}

// Only "on" and "off" are taken for the switch, on the website and on a
// push alike; any other value on disk, a key without a value and a file that
// does not read count as off. A Settings save of an engagement whose AI is
// off keeps the key.
func TestEngagementAIValues(t *testing.T) {
	for src, want := range map[string]struct{ off, ok bool }{
		"name: A\n":            {false, true},
		"name: A\nai: on\n":    {false, true},
		"name: A\nai: off\n":   {true, true},
		"name: A\nai: \"off\"": {true, true},
		"name: A\nai: of\n":    {true, false},
		"name: A\nai: no\n":    {true, false},
		"name: A\nai: false\n": {true, false},
		"name: A\nai:\n":       {true, false},
		"name: A\nai: ~\n":     {true, false},
		"name: A\nai: Off\n":   {true, false},
	} {
		e, err := ParseEngagement([]byte(src))
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}
		e.Type = "pentest"
		ps := EngagementProblems(nil, e)
		if e.AIOff() != want.off || (len(ps) == 0) != want.ok {
			t.Errorf("%q: off %v, problems %v", src, e.AIOff(), ps)
		}
		if !want.ok && !strings.Contains(strings.Join(ps, "; "), "ai must be on or off") {
			t.Errorf("%q: problems %v", src, ps)
		}
		// a push that changes nothing else is refused the same way
		prev := e
		prev.AI = ""
		if ps := EngagementProblems(&prev, e); (len(ps) == 0) != want.ok {
			t.Errorf("%q as a change: problems %v", src, ps)
		}
	}

	s, dir, fd := ready(t)
	if err := s.SetEngagementAI(eng, false, uDora); err != nil {
		t.Fatal(err)
	}
	e, err := s.Engagement(eng)
	if err != nil {
		t.Fatal(err)
	}
	e.Name, e.End = "ACME portal", "2026-12-24"
	if err := s.UpdateEngagement(e, uDora); err != nil {
		t.Fatalf("a Settings save where AI is off: %v", err)
	}
	if e, err = s.Engagement(eng); err != nil || e.Name != "ACME portal" || !e.AIOff() {
		t.Fatalf("after the save: %+v %v", e, err)
	}
	// a save cannot turn it on: the form's value is not read
	e.AI = ""
	e.Client = "ACME Ltd"
	if err := s.UpdateEngagement(e, uDora); err != nil {
		t.Fatal(err)
	}
	if e, err = s.Engagement(eng); err != nil || e.Client != "ACME Ltd" || !e.AIOff() {
		t.Fatalf("after a save without the key: %+v %v", e, err)
	}
	// a file that does not read, and a typo, are off
	p := filepath.Join(dir, "engagements", eng, "engagement.yaml")
	for _, body := range []string{"name: [\n", "name: A\ntype: pentest\nai: of\n", "name: A\ntype: pentest\nai: [off]\n"} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		ref, _, err := s.read(eng, fd, nil)
		if err != nil || !ref.F.Meta.NoAI {
			t.Fatalf("%q: read as on (%v)", body, err)
		}
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if ref, _, err := s.read(eng, fd, nil); err != nil || !ref.F.Meta.NoAI {
		t.Fatalf("no engagement.yaml: read as on (%v)", err)
	}
}

// A retest is the same client's text: it takes its source's switch when it
// is made.
func TestRetestTakesTheAISwitch(t *testing.T) {
	s, dir := srcFixture(t)
	if err := s.SetEngagementAI(eng, false, uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRetest(Engagement{ID: "rt", Name: "RT"}, eng, []string{"F-001-sql-injection"}, "", uDora); err != nil {
		t.Fatal(err)
	}
	e, err := s.Engagement("rt")
	if err != nil || !e.AIOff() || e.AI != "off" {
		t.Fatalf("the retest: %+v %v", e, err)
	}
	refs, err := s.ListFindings("rt")
	if err != nil || len(refs) != 1 || !refs[0].F.Meta.NoAI || refs[0].F.Meta.Engagement != "rt" {
		t.Fatalf("the retest's findings: %+v %v", refs, err)
	}
	// a source that takes AI makes a retest that takes it
	if err := s.SetEngagementAI(eng, true, uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRetest(Engagement{ID: "rt2", Name: "RT2"}, eng, []string{"F-001-sql-injection"}, "", uDora); err != nil {
		t.Fatal(err)
	}
	if e, err := s.Engagement("rt2"); err != nil || e.AIOff() {
		t.Fatalf("the second retest: %+v %v", e, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "engagements", "rt2", "engagement.yaml")); strings.Contains(string(b), "ai:") {
		t.Fatalf("the second retest's file:\n%s", b)
	}
}

// Fix with AI is refused at the press where the engagement takes no AI, with
// words, and nothing is asked. Switched off while a fix runs, the items left
// are answered with the words.
func TestFixRefusedWhereAIIsOff(t *testing.T) {
	s, _, fd, ff := fixReady(t, "a foo here", "", removeFoo)
	if err := s.SetEngagementAI(eng, false, uDora); err != nil {
		t.Fatal(err)
	}
	err := s.StartFix(eng, fd, uAlice)
	s.WaitChecks()
	if !errors.Is(err, ErrInvalidValue) || !strings.HasSuffix(err.Error(), ": AI is off for this engagement") {
		t.Fatalf("a fix where AI is off: %v", err)
	}
	if ff.calls != 0 || s.FixRunning(eng, fidOf(t, s, fd)) || len(aiReplies(t, s, fd)) != 0 {
		t.Fatalf("the fix ran: %d calls, replies %+v", ff.calls, aiReplies(t, s, fd))
	}

	extra := "- id: no-zz\n  target: section:Impact\n  regex_forbid: 'zz'\n  level: warning\n  message: Avoid zz\n"
	var s2 *Store
	s2, _, fd2, ff2 := fixReady(t, "a foo here\n\nsome zz there", extra, func(v rules.Violation, _, body string) (string, error) {
		if err := s2.SetEngagementAI(eng, false, uDora); err != nil {
			return "", err
		}
		return strings.ReplaceAll(body, "foo", "bar"), nil
	})
	fixed(t, s2, fd2)
	got := aiReplies(t, s2, fd2)
	if ff2.calls != 1 || len(got) != 2 {
		t.Fatalf("%d calls, replies %+v", ff2.calls, got)
	}
	if got[1].Text != "Not fixed: AI is off for this engagement." {
		t.Fatalf("the item after the switch: %+v", got)
	}
}
