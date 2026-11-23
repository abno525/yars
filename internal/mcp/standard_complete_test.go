package mcp

import (
	"strings"
	"testing"
)

// The standard workflow has no complete (the simple workflow's step): over
// MCP it stays an unknown action, refused as invalid with the actions there
// are, as before the simple workflow came; with a base read long ago too
// (no conflict: there is nothing to read again for).
func TestMCPStandardCompleteUnknown(t *testing.T) {
	f := newFx(t)
	withRules(t, f)
	for _, base := range []string{"", "a hash the finding never had"} {
		text, isErr := f.call(dora, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": "complete", "base": base})
		if !isErr {
			t.Fatalf("base %q: done: %s", base, text)
		}
		m := object(t, "transition", text)
		if m["code"] != "invalid" || !strings.HasPrefix(message(t, text), "unknown action (submit, return, clear or sign_off, approve,") {
			t.Errorf("base %q: %s", base, text)
		}
	}
}
