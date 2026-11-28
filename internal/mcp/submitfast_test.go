package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/abno525/yars/internal/rules"
)

// transition submit runs the pattern and built-in rules only: an error-level
// script rule does not run and does not hold it (before: every rule ran in
// the call and the script's error refused it).
func TestTransitionSubmitRunsNoScript(t *testing.T) {
	f := newFx(t)
	st := f.s.Store
	if err := st.SetReviewers("acme", "F-001-sql-injection", []string{"bob"}, alice); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSeverity("acme", "F-001-sql-injection", "high", "", alice.GitAuthor()); err != nil {
		t.Fatal(err)
	}
	rd := filepath.Join(f.dir, ".yars", "rules")
	os.MkdirAll(rd, 0o755)
	marker := filepath.Join(t.TempDir(), "ran")
	os.WriteFile(filepath.Join(rd, "r.yaml"), []byte("- id: scripted\n  script: mark.sh\n"), 0o644)
	os.WriteFile(filepath.Join(rd, "mark.sh"), []byte("#!/bin/sh\ncat >/dev/null\necho run >> "+marker+"\necho '[{\"message\":\"script says no\",\"target\":\"title\"}]'\n"), 0o755)
	eng := rules.NewEngine(rules.DirFor(f.dir), f.s.Cfg)
	f.s.Store.Linter, f.s.Rules = eng, eng
	text, isErr := f.call(alice, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": "submit"})
	if isErr {
		t.Fatalf("submit over a script rule: %s", text)
	}
	if ref, err := st.Finding("acme", "001"); err != nil || ref.F.Meta.Status != "verification" {
		t.Fatalf("status %v %v", ref.F.Meta.Status, err)
	}
	if n := scriptRuns(marker); n != 0 {
		t.Fatalf("submit ran the script %d times", n)
	}
}
