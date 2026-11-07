package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// An argument of the wrong JSON type is refused by name and nothing
// changes; it is never read as an empty string or false.
func TestMCPArgumentTypes(t *testing.T) {
	f := newFx(t)
	f.ok(alice, "update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "Kept."})
	f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": "bob"})
	head := f.lastCommit()
	for _, c := range []struct {
		tool string
		args map[string]any
		want string
	}{
		{"update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": []any{"new"}}, `argument "body" must be a string`},
		{"update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": nil}, `argument "body" must be a string`},
		{"set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": []any{"bob"}}, `argument "value" must be a string`},
		{"set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "severity", "value": 3}, `argument "value" must be a string`},
		{"list_findings", map[string]any{"engagement": 1}, `argument "engagement" must be a string`},
		{"lint_finding", map[string]any{"engagement": "acme", "finding": "F-001", "all": "true"}, `argument "all" must be a boolean`},
		{"update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact"}, `missing argument "body"`},
		{"set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers"}, `missing argument "value"`},
	} {
		if out, isErr := f.call(alice, c.tool, c.args); !isErr || out != c.want {
			t.Errorf("%s %v: %v %q, want %q", c.tool, c.args, isErr, out, c.want)
		}
	}
	if got := f.lastCommit(); got != head {
		t.Fatalf("a refused call committed: %s", got)
	}
	var rd struct {
		Markdown string `json:"finding_md"`
		State    struct {
			Reviewers []string `json:"reviewers"`
		} `json:"state"`
	}
	json.Unmarshal([]byte(f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})), &rd)
	if !strings.Contains(rd.Markdown, "Kept.") || strings.Join(rd.State.Reviewers, ",") != "bob" {
		t.Fatalf("changed by a refused call: %+v", rd)
	}
}

// Bidi controls are dropped from a title on save: "Upload <RLO>gnp.exe"
// would read "Upload exe.png".
func TestMCPTitleBidiStripped(t *testing.T) {
	f := newFx(t)
	title := func(id string) string {
		var rd struct {
			Markdown string `json:"finding_md"`
		}
		json.Unmarshal([]byte(f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": id})), &rd)
		return rd.Markdown
	}
	f.ok(alice, "create_finding", map[string]any{"engagement": "acme", "title": "Upload ‮gnp.exe"})
	if md := title("F-002"); !strings.Contains(md, "title: Upload gnp.exe\n") {
		t.Fatalf("created:\n%s", md)
	}
	f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "title", "value": "⁧SQL⁩ injection‏"})
	if md := title("F-001"); !strings.Contains(md, "title: SQL injection\n") {
		t.Fatalf("edited:\n%s", md)
	}
}

// An unknown template is named as such, not a bare "not found" that reads
// like an unknown engagement.
func TestMCPUnknownTemplate(t *testing.T) {
	f := newFx(t)
	for _, slug := range []string{"nope", "../../etc"} {
		out, isErr := f.call(alice, "create_finding", map[string]any{"engagement": "acme", "title": "x", "template": slug})
		if want := `unknown template "` + slug + `"; see list_templates`; !isErr || out != want {
			t.Errorf("%s: %v %q, want %q", slug, isErr, out, want)
		}
	}
	if out, _ := f.call(alice, "create_finding", map[string]any{"engagement": "nope", "title": "x", "template": "nope"}); out != "not found" {
		t.Errorf("unknown engagement: %q", out)
	}
}

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
