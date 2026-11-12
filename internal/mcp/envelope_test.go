package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"yars/internal/rules"
	"yars/internal/store"
	"yars/internal/workflow"
)

// object parses a tool's text as one JSON object.
func object(t *testing.T, name, text string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("%s: not a JSON object: %v\n%.300s", name, err, text)
	}
	return m
}

// message is the "message" of a tool's answer (a refusal's too).
func message(t *testing.T, text string) string {
	t.Helper()
	s, _ := object(t, "answer", text)["message"].(string)
	return s
}

// itemsOf decodes the "items" of a list answer into v.
func itemsOf(t *testing.T, text string, v any) {
	t.Helper()
	var w struct {
		Items json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal([]byte(text), &w); err != nil || w.Items == nil {
		t.Fatalf("not a list answer: %v\n%.300s", err, text)
	}
	if err := json.Unmarshal(w.Items, v); err != nil {
		t.Fatalf("items: %v\n%.300s", err, text)
	}
}

// withRules gives the fixture a rules engine (start_check needs one).
func withRules(t *testing.T, f *fx) {
	t.Helper()
	rd := filepath.Join(f.dir, ".yars", "rules")
	os.MkdirAll(rd, 0o755)
	os.WriteFile(filepath.Join(rd, "r.yaml"), []byte("- id: no-sql\n  target: title\n  regex_forbid: 'SQL'\n"), 0o644)
	eng := rules.NewEngine(rd, f.s.Cfg)
	f.s.Rules, f.s.Store.Linter = eng, eng
}

// Every tool, called right, answers one JSON object with "ok": true.
func TestEverySuccessIsAnObjectWithOK(t *testing.T) {
	f := newFx(t)
	withRules(t, f)
	defer f.s.Store.WaitChecks()
	fd := map[string]any{"engagement": "acme", "finding": "F-001"}
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{"engagement": "acme", "finding": "F-001"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	thread := ""
	calls := []struct {
		tool string
		args func() map[string]any
	}{
		{"list_engagements", func() map[string]any { return map[string]any{} }},
		{"list_findings", func() map[string]any { return map[string]any{"engagement": "acme"} }},
		{"read_finding", func() map[string]any { return fd }},
		{"list_templates", func() map[string]any { return map[string]any{} }},
		{"create_finding", func() map[string]any { return map[string]any{"engagement": "acme", "title": "Open redirect"} }},
		{"update_section", func() map[string]any { return with(map[string]any{"section": "Impact", "body": "Full read."}) }},
		{"set_field", func() map[string]any {
			return with(map[string]any{"field": "title", "value": "SQL injection in search"})
		}},
		{"add_chat_message", func() map[string]any { return with(map[string]any{"text": "a question"}) }},
		{"resolve_thread", func() map[string]any { return with(map[string]any{"thread": thread}) }},
		{"lint_finding", func() map[string]any { return fd }},
		{"start_check", func() map[string]any { return fd }},
		{"get_check_results", func() map[string]any { return fd }},
		{"list_notifications", func() map[string]any { return map[string]any{} }},
		{"transition", func() map[string]any { return with(map[string]any{"action": "withdraw", "reason": "duplicate"}) }},
	}
	seen := map[string]bool{}
	for _, c := range calls {
		seen[c.tool] = true
		text, isErr := f.call(alice, c.tool, c.args())
		if isErr {
			t.Fatalf("%s failed: %s", c.tool, text)
		}
		m := object(t, c.tool, text)
		if m["ok"] != true {
			t.Fatalf("%s: no ok: %s", c.tool, text)
		}
		if c.tool == "add_chat_message" {
			thread, _ = m["id"].(string)
		}
		if c.tool == "start_check" {
			f.s.Store.WaitChecks()
		}
	}
	for _, tl := range tools {
		if !seen[tl.name] {
			t.Errorf("tool %s not called", tl.name)
		}
	}
}

// A client of the plain answers is still told what happened.
func TestSuccessKeepsMessage(t *testing.T) {
	f := newFx(t)
	text := f.ok(alice, "update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "Full read."})
	if text != `{"ok":true,"message":"updated Impact"}` {
		t.Fatalf("%s", text)
	}
}

func TestErrorCodes(t *testing.T) {
	cases := []struct {
		err  error
		code string
	}{
		{&workflow.Denied{Reason: "no"}, "not_allowed"},
		{fmt.Errorf("edit: %w", store.ErrConflict), "conflict"},
		{store.ErrNotFound, "not_found"},
		{store.ErrArchived, "archived"},
		{store.ErrNoDB, "no_database"},
		{store.ErrBusy, "busy"},
		{fmt.Errorf("%w: bad", store.ErrInvalidValue), "invalid"},
		{errors.New(`missing argument "finding"`), "invalid"},
		{ambiguous{id: "F-001", dirs: []string{"a", "b"}}, "invalid"},
	}
	for _, c := range cases {
		if got := codeOf(c.err); got != c.code {
			t.Errorf("%v: %s, want %s", c.err, got, c.code)
		}
		m := object(t, c.code, fail(c.err))
		if m["ok"] != false || m["code"] != c.code || m["message"] != explain(c.err) {
			t.Errorf("fail(%v) = %v", c.err, m)
		}
	}
	// over the wire: a refusal is isError with the object
	f := newFx(t)
	text, isErr := f.call(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-009"})
	if m := object(t, "read_finding", text); !isErr || m["code"] != "not_found" {
		t.Fatalf("%v %s", isErr, text)
	}
	text, isErr = f.call(alice, "read_finding", map[string]any{"engagement": "acme"})
	if m := object(t, "read_finding", text); !isErr || m["code"] != "invalid" || m["message"] != `missing argument "finding"` {
		t.Fatalf("%v %s", isErr, text)
	}
}

// Lists are {"ok": true, "items": […], "next": ""}.
func TestListsHaveItemsAndNext(t *testing.T) {
	f := newFx(t)
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"list_engagements", map[string]any{}},
		{"list_findings", map[string]any{"engagement": "acme"}},
		{"list_templates", map[string]any{}},
		{"list_notifications", map[string]any{}},
		{"lint_finding", map[string]any{"engagement": "acme", "finding": "F-001"}},
	} {
		m := object(t, c.tool, f.ok(alice, c.tool, c.args))
		if _, ok := m["items"].([]any); !ok || m["next"] != "" || m["ok"] != true {
			t.Errorf("%s: %v", c.tool, m)
		}
	}
}
