package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/finding"
	"yars/internal/rules"
	"yars/internal/workflow"
)

func withRules(t *testing.T, s *Store, dir, body string) {
	t.Helper()
	rd := filepath.Join(dir, ".yars", "rules")
	os.MkdirAll(rd, 0o755)
	if err := os.WriteFile(filepath.Join(rd, "style.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Linter = rules.NewEngine(rd, config.Default())
}

// editingLinter edits the finding while "checking" it, simulating a write
// that lands during a slow script/AI run.
type editingLinter struct{ s *Store }

func (l editingLinter) Lint(_ context.Context, f *finding.Finding, _ rules.Kind) []rules.Violation {
	l.s.UpdateSection(eng, "F-001-sql-injection", "Impact", "edited during lint", "", alice)
	return nil
}

func TestSubmitRefusedIfChangedDuringLint(t *testing.T) {
	s, _, fd := ready(t)
	s.Linter = editingLinter{s}
	err := s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if !denied(err) || !strings.Contains(err.Error(), "changed while its checks ran") {
		t.Fatalf("err %v", err)
	}
	if load(t, s, fd).F.Meta.Status != "draft" {
		t.Fatal("status changed")
	}
}

func TestApproveBlockedByRule(t *testing.T) {
	s, dir, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	withRules(t, s, dir, "- id: t\n  target: title\n  regex_forbid: 'SQL'\n  message: no SQL in titles\n")
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); !denied(err) || !strings.Contains(err.Error(), "no SQL in titles") {
		t.Fatalf("err %v", err)
	}
}

func TestSubmitBlockedByRule(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, `
- id: no-injection-word
  target: title
  regex_forbid: 'injection'
  message: Do not say injection
- id: soft
  target: title
  regex_forbid: 'SQL'
  level: warning
`)
	err := s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if !denied(err) || !strings.Contains(err.Error(), "Do not say injection") || strings.Contains(err.Error(), "soft") {
		t.Fatalf("err %v", err)
	}
	if load(t, s, fd).F.Meta.Status != "draft" {
		t.Fatal("status changed")
	}
	withRules(t, s, dir, "- id: soft\n  target: title\n  regex_forbid: 'SQL'\n  level: warning\n")
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatalf("warning blocked submit: %v", err)
	}
}
