package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/workflow"
)

// Submit asks for the pattern and built-in rules only: what a script or an
// AI rule would report does not hold it and is not asked for. Before, Submit
// ran every rule in the request (up to 90 s) and a script's error refused
// it.
func TestSubmitRunsFastRulesOnly(t *testing.T) {
	s, _, fd := ready(t)
	var got []rules.Kind
	s.Linter = kindLinter{&got}
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("submit ran no rules")
	}
	for _, k := range got {
		if k != rules.Fast {
			t.Fatalf("submit asked for %v", got)
		}
	}
	if st := load(t, s, fd).F.Meta.Status; st != "verification" {
		t.Fatalf("status %s", st)
	}
}

// scriptSays is a script that reports one error on the title and notes each
// run in the file marker.
func scriptSays(marker string) string {
	return "#!/bin/sh\ncat >/dev/null\necho run >> " + marker + "\necho '[{\"message\":\"The script says no\",\"quote\":\"SQL\",\"target\":\"title\"}]'\n"
}

// A script rule is not run by Submit and does not hold it; the Check run has
// it, and Sign off and Approve read that run: before any run they wait for
// one, after it the script's error holds them. With Require Check off,
// Approve still runs every rule itself.
func TestSubmitDoesNotRunScripts(t *testing.T) {
	s, dir, fd := ready(t)
	marker := filepath.Join(t.TempDir(), "ran")
	withRules(t, s, dir, "- id: scr\n  script: check.sh\n")
	if err := os.WriteFile(filepath.Join(dir, ".yars", "rules", "check.sh"), []byte(scriptSays(marker)), 0o755); err != nil {
		t.Fatal(err)
	}
	runs := func() int {
		b, _ := os.ReadFile(marker)
		return strings.Count(string(b), "run")
	}
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatalf("submit over a script rule: %v", err)
	}
	if runs() != 0 {
		t.Fatalf("submit ran the script %d times", runs())
	}
	if st := load(t, s, fd).F.Meta.Status; st != "verification" {
		t.Fatalf("status %s", st)
	}
	// no run yet: the gate still asks for one
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); !denied(err) || !strings.Contains(err.Error(), GateNoRun) {
		t.Fatalf("sign off before a check: %v", err)
	}
	if runs() != 0 {
		t.Fatalf("sign off ran the script %d times", runs())
	}
	checkNow(t, s, fd)
	if runs() != 1 {
		t.Fatalf("the check ran the script %d times", runs())
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); !denied(err) || !strings.Contains(err.Error(), "The script says no") {
		t.Fatalf("sign off over the run's script error: %v", err)
	}
	// signed off while it was dismissed, then restored: Approve reads the run
	if err := s.DismissWhy(eng, fd, "scr", "title", "SQL", "for the sign-off", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatalf("sign off with the error dismissed: %v", err)
	}
	if err := s.Undismiss(eng, fd, "scr", "title", "SQL", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); !denied(err) || !strings.Contains(err.Error(), "The script says no") {
		t.Fatalf("approve over the run's script error: %v", err)
	}
	if runs() != 1 {
		t.Fatalf("sign off and approve ran the script (%d runs)", runs())
	}
	// taken back and submitted again: still not held by the stored error
	if err := s.Transition(eng, fd, workflow.TakeBack, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatalf("submit over a stored script error: %v", err)
	}
}

// An error of a pattern rule still refuses Submit, in the words the allowed
// actions (BlockingNow) give for it.
func TestSubmitStillHeldByPatternError(t *testing.T) {
	s, dir, fd := ready(t)
	marker := filepath.Join(t.TempDir(), "ran")
	withRules(t, s, dir, "- id: t\n  target: title\n  regex_forbid: 'SQL'\n  message: no SQL in titles\n- id: scr\n  script: check.sh\n")
	if err := os.WriteFile(filepath.Join(dir, ".yars", "rules", "check.sh"), []byte(scriptSays(marker)), 0o755); err != nil {
		t.Fatal(err)
	}
	err := s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if !denied(err) || !strings.HasSuffix(err.Error(), ": no SQL in titles") {
		t.Fatalf("submit over a pattern error: %v", err)
	}
	now, nerr := s.BlockingNow(eng, fd, workflow.Submit, uAlice)
	if nerr != nil || now != err.Error() {
		t.Fatalf("the allowed actions say %q (%v), the transition %q", now, nerr, err)
	}
	if b, _ := os.ReadFile(marker); len(b) != 0 {
		t.Fatalf("the script ran: %q", b)
	}
}
