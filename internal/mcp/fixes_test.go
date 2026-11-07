package mcp

import (
	"encoding/json"
	"testing"
)

// read_finding's can_edit is false while the engagement is archived: every
// write would be refused.
func TestMCPCanEditArchived(t *testing.T) {
	f := newFx(t)
	canEdit := func() bool {
		var rd struct {
			CanEdit bool `json:"can_edit"`
		}
		json.Unmarshal([]byte(f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})), &rd)
		return rd.CanEdit
	}
	if !canEdit() {
		t.Fatal("author cannot edit a draft")
	}
	if err := f.s.Store.Archive("acme", dora); err != nil {
		t.Fatal(err)
	}
	if canEdit() {
		t.Fatal("can_edit true on an archived engagement")
	}
}
