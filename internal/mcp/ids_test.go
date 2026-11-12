package mcp

import (
	"os"
	"os/exec"
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

// addFolder writes a finding folder copied from F-001 with its id line
// changed, and commits it (the index reads committed findings).
func addFolder(t *testing.T, f *fx, dir, id string) {
	t.Helper()
	ed := filepath.Join(f.dir, "engagements", "acme")
	src, err := os.ReadFile(filepath.Join(ed, "findings", "F-001-sql-injection", "finding.md"))
	if err != nil {
		t.Fatal(err)
	}
	src = []byte(strings.Replace(string(src), "id: F-001", "id: "+id, 1))
	os.MkdirAll(filepath.Join(ed, "findings", dir), 0o755)
	if err := os.WriteFile(filepath.Join(ed, "findings", dir, "finding.md"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][]string{{"add", "-A"}, {"-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "add " + dir}} {
		if out, err := exec.Command("git", append([]string{"-C", ed}, c...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", c, err, out)
		}
	}
}

// A folder whose name has another number than its ID: the ID names both it
// and the folder of that number (ambiguous); its own number names it.
func TestIDByFrontMatterToo(t *testing.T) {
	f := newFx(t)
	addFolder(t, f, "F-002-renamed", "F-001")
	text, isErr := f.call(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})
	if !isErr || !strings.Contains(message(t, text), "(F-001-sql-injection, F-002-renamed)") {
		t.Fatalf("F-001: %.300s", text)
	}
	if text := f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-002"}); !strings.Contains(text, `"dir":"F-002-renamed"`) {
		t.Fatalf("F-002: %.300s", text)
	}
}

// A folder named just the ID wins; a folder whose name is an ID in another
// form (F-7) is still reached by that name.
func TestIDExactFolder(t *testing.T) {
	f := newFx(t)
	addFolder(t, f, "F-001", "F-001")
	if text := f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"}); !strings.Contains(text, `"dir":"F-001"`) {
		t.Fatalf("F-001: %.300s", text)
	}
	addFolder(t, f, "F-7", "F-7")
	addFolder(t, f, "F-007-xss", "F-007")
	if text := f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-7"}); !strings.Contains(text, `"dir":"F-7"`) {
		t.Fatalf("F-7: %.300s", text)
	}
}

// A finding that does not parse says why when named by its ID, as by its
// folder name; it is not "not found".
func TestIDBrokenFindingSaysWhy(t *testing.T) {
	f := newFx(t)
	p := filepath.Join(f.dir, "engagements", "acme", "findings", "F-001-sql-injection", "finding.md")
	if err := os.WriteFile(p, []byte("---\nid: [unclosed\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	text, isErr := f.call(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})
	if m := object(t, "read_finding", text); !isErr || m["code"] == "not_found" {
		t.Fatalf("%s", text)
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

// The server's instructions and the tools that take a status name them;
// the instructions name the new tools an assistant starts with.
func TestInstructionsNameStatuses(t *testing.T) {
	const all = "draft, verification, complete, reported, withdrawn"
	if !strings.Contains(instructions, all) {
		t.Errorf("instructions: %s", instructions)
	}
	for _, name := range []string{"whoami", "get_config", "read_chat", "fix_checks"} {
		if !strings.Contains(instructions, name) {
			t.Errorf("instructions lack %s", name)
		}
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
