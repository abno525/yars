package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// create_finding refuses the titles set_field title refuses.
func TestMCPCreateFindingTitle(t *testing.T) {
	f := newFx(t)
	for _, title := range []string{strings.Repeat("a", 201), "A\nB", "A\rB", "A B", "A\x1b[31mB", "A\u0085B"} {
		if out, isErr := f.call(alice, "create_finding", map[string]any{"engagement": "acme", "title": title}); !isErr || !strings.Contains(out, "one line of 1–200 characters") {
			t.Errorf("title %q: %v %s", title, isErr, out)
		}
	}
	f.ok(alice, "create_finding", map[string]any{"engagement": "acme", "title": strings.Repeat("a", 200)})
	if out, isErr := f.call(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "title", "value": "A B"}); !isErr {
		t.Errorf("set_field title with a paragraph separator: %s", out)
	}
}

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
