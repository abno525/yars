package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// R2: a finding id in any case and with or without its zeros names the
// same finding.
func TestFindingIDNormalised(t *testing.T) {
	f := newFx(t)
	for _, id := range []string{"f-1", "F-1", "F-001", "f-001", "F-0001", "1", "001"} {
		text, isErr := f.call(alice, "read_finding", map[string]any{"engagement": "acme", "finding": id})
		if isErr || !strings.Contains(text, "F-001-sql-injection") {
			t.Errorf("%s: %.200s", id, text)
		}
	}
	if got := normalID("f-7"); got != "F-007" {
		t.Errorf("normalID(f-7) = %q", got)
	}
	if got := normalID("F-1234"); got != "F-1234" {
		t.Errorf("normalID(F-1234) = %q", got)
	}
	if got := normalID("F-001-sql-injection"); got != "F-001-sql-injection" {
		t.Errorf("a folder name changed: %q", got)
	}
}

// Two folders holding F-001: the id is refused as ambiguous, never the
// first match; each folder name still works.
func TestAmbiguousIDRefused(t *testing.T) {
	f := newFx(t)
	fd := filepath.Join(f.dir, "engagements", "acme", "findings")
	src, err := os.ReadFile(filepath.Join(fd, "F-001-sql-injection", "finding.md"))
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(fd, "F-001-copy"), 0o755)
	if err := os.WriteFile(filepath.Join(fd, "F-001-copy", "finding.md"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"F-001", "f-1", "1"} {
		text, isErr := f.call(alice, "read_finding", map[string]any{"engagement": "acme", "finding": id})
		if !isErr || !strings.Contains(text, "F-001 names more than one finding folder (F-001-copy, F-001-sql-injection); use the folder name") {
			t.Errorf("%s: %.300s", id, text)
		}
	}
	for _, dir := range []string{"F-001-copy", "F-001-sql-injection"} {
		f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": dir})
	}
}

func TestUnknownStatusListsValid(t *testing.T) {
	f := newFx(t)
	text, isErr := f.call(alice, "list_findings", map[string]any{"engagement": "acme", "status": "open"})
	if text = message(t, text); !isErr || !strings.Contains(text, `"open"`) || !strings.Contains(text, "draft, verification, complete, reported, withdrawn") {
		t.Fatalf("%s", text)
	}
	f.ok(alice, "list_findings", map[string]any{"engagement": "acme", "status": "draft"})
}

func TestUnknownSeverityListsValid(t *testing.T) {
	f := newFx(t)
	text, isErr := f.call(alice, "list_findings", map[string]any{"engagement": "acme", "severity": "severe"})
	if text = message(t, text); !isErr || !strings.Contains(text, `"severe"`) || !strings.Contains(text, "critical, high, medium, low, info") {
		t.Fatalf("%s", text)
	}
	f.ok(alice, "list_findings", map[string]any{"engagement": "acme", "severity": "high"})
}

// The server's instructions and the tools that take a status name them.
func TestInstructionsNameStatuses(t *testing.T) {
	const all = "draft, verification, complete, reported, withdrawn"
	if !strings.Contains(instructions, all) {
		t.Errorf("instructions: %s", instructions)
	}
	for _, name := range []string{"list_findings", "transition"} {
		tl := toolByName[name]
		text := tl.desc
		for _, p := range append(tl.required, tl.optional...) {
			text += " " + p.desc
		}
		if !strings.Contains(text, all) {
			t.Errorf("%s: %s", name, text)
		}
	}
}
