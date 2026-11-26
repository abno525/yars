package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/rules"
)

// D25 through MCP: Sign off and Approve go through the store's gate, so an
// open check warning refuses them with the warning's text.
func TestMCPSignOffRefusedWithOpenWarning(t *testing.T) {
	f := newFx(t)
	rd := filepath.Join(t.TempDir(), "rules")
	os.MkdirAll(rd, 0o755)
	os.WriteFile(filepath.Join(rd, "style.yaml"), []byte("- id: soft\n  target: title\n  regex_forbid: 'SQL'\n  level: warning\n  message: say what SQL means\n"), 0o644)
	f.s.Store.Linter = rules.NewEngine(rd, config.Default())
	f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": "bob"})
	f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "severity", "value": "high"})
	tr := func(u config.User, action string) (string, bool) {
		return f.call(u, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": action})
	}
	if text, isErr := tr(alice, "submit"); isErr {
		t.Fatalf("a warning blocked submit: %s", text)
	}
	if text, isErr := tr(bob, "sign_off"); !isErr || !strings.Contains(text, "say what SQL means") {
		t.Fatalf("sign off with an open warning: %v %s", isErr, text)
	}
	if err := f.s.Store.DismissWhy("acme", "001", "soft", "", "SQL", "fine here", bob); err != nil {
		t.Fatal(err)
	}
	// R1: Require Check (on by default) wants a check run on this content
	if text, isErr := tr(bob, "sign_off"); !isErr || !strings.Contains(text, "run check first: no check run yet") {
		t.Fatalf("sign off without a check run: %v %s", isErr, text)
	}
	if _, err := f.s.Store.StartCheck("acme", "001", bob); err != nil {
		t.Fatal(err)
	}
	f.s.Store.WaitChecks()
	if text, isErr := tr(bob, "sign_off"); isErr {
		t.Fatalf("sign off once dismissed and checked: %s", text)
	}
	// an edit since the run: the same refusal names it
	if err := f.s.Store.UpdateSection("acme", "001", "Impact", "More.", "", alice); err != nil {
		t.Fatal(err)
	}
	if text, isErr := tr(bob, "sign_off"); !isErr || !strings.Contains(text, "run check first: the content changed since the last check") {
		t.Fatalf("sign off after an edit: %v %s", isErr, text)
	}
	f.s.Store.StartCheck("acme", "001", bob)
	f.s.Store.WaitChecks()
	if text, isErr := tr(bob, "sign_off"); isErr {
		t.Fatalf("sign off once checked again: %s", text)
	}
	if err := f.s.Store.Undismiss("acme", "001", "soft", "", "SQL", bob); err != nil {
		t.Fatal(err)
	}
	if text, isErr := tr(dora, "approve"); !isErr || !strings.Contains(text, "say what SQL means") {
		t.Fatalf("approve with an open warning: %v %s", isErr, text)
	}
}
