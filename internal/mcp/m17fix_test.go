package mcp

import (
	"strings"
	"testing"
)

// A structure saved in Admin › Structure (Store.SetConfig) applies to the
// MCP tools without a restart.
func TestMCPFollowsSavedStructure(t *testing.T) {
	f := newFx(t)
	c := f.s.Store.Config()
	c.Sections = append(c.Sections, "Business context")
	c.DetailsRows = []string{"Endpoint", "Cause"}
	f.s.Store.SetConfig(c)

	f.ok(alice, "update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Business context", "body": "Payments."})
	f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "details.Endpoint", "value": "/pay"})
	if text, isErr := f.call(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "details.Location", "value": "x"}); !isErr || !strings.Contains(text, "Location") {
		t.Fatalf("old row accepted: %s", text)
	}
}
