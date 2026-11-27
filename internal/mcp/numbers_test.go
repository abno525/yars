package mcp

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
)

// pre1 6.5: limit and cursor are taken as JSON numbers too (whole ones), as
// most clients send them; a string still works, and a number that is no
// such limit or cursor is refused with the words a string gets. The schema
// says integer for limit. Other arguments keep their type.
func TestPagingTakesNumbers(t *testing.T) {
	f := newFx(t)
	for i := 2; i <= 10; i++ {
		if _, err := f.s.Store.CreateFinding("acme", fmt.Sprintf("Finding %d", i), alice.GitAuthor()); err != nil {
			t.Fatal(err)
		}
	}
	page := func(a map[string]any) (int, string) {
		t.Helper()
		a["engagement"] = "acme"
		text, isErr := f.call(alice, "list_findings", a)
		if isErr {
			t.Fatalf("%v: %s", a, text)
		}
		var items []any
		itemsOf(t, text, &items)
		next, _ := object(t, "page", text)["next"].(string)
		return len(items), next
	}
	if n, next := page(map[string]any{"limit": 7}); n != 7 || next != "7" {
		t.Fatalf("limit 7 as a number: %d items, next %q", n, next)
	}
	if n, next := page(map[string]any{"limit": 7.0, "cursor": 7}); n != 3 || next != "" {
		t.Fatalf("cursor 7 as a number: %d items, next %q", n, next)
	}
	if n, next := page(map[string]any{"limit": "7", "cursor": "7"}); n != 3 || next != "" {
		t.Fatalf("as strings: %d items, next %q", n, next)
	}
	if n, next := page(map[string]any{"limit": 200, "cursor": 0}); n != 10 || next != "" {
		t.Fatalf("limit 200, cursor 0: %d items, next %q", n, next)
	}
	for _, c := range []struct {
		arg  string
		v    any
		says string
	}{
		{"limit", 1.5, "limit must be a whole number from 1 to 200"}, {"limit", 0, "limit must be a whole number from 1 to 200"},
		{"limit", -1, "limit must be a whole number from 1 to 200"}, {"limit", 201, "limit must be a whole number from 1 to 200"},
		{"limit", 1e30, "limit must be a whole number from 1 to 200"},
		{"cursor", 1.5, "cursor must be the next of an earlier answer"}, {"cursor", -1, "cursor must be the next of an earlier answer"},
		{"limit", true, `argument "limit" must be a whole number`}, {"cursor", []any{1}, `argument "cursor" must be a whole number`},
		{"limit", nil, `argument "limit" must be a whole number`},
		{"q", 7, `argument "q" must be a string`},
	} {
		text, isErr := f.call(alice, "list_findings", map[string]any{"engagement": "acme", c.arg: c.v})
		if m := object(t, c.arg, text); !isErr || m["code"] != "invalid" || !strings.HasPrefix(message(t, text), c.says) {
			t.Errorf("%s %v: %s", c.arg, c.v, text)
		}
	}
	// the notifications' cursor is an id: a number too
	d := f.s.Store.DB()
	d.AddUser(alice)
	var ids []int64
	for i := range 3 {
		id, _ := d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "acme", Fid: "F-001", Actor: "bob", Text: fmt.Sprint(i)})
		ids = append(ids, id)
	}
	text := f.ok(alice, "list_notifications", map[string]any{"limit": 1, "cursor": ids[2]})
	var notes []struct{ ID int64 }
	itemsOf(t, text, &notes)
	if len(notes) != 1 || notes[0].ID != ids[1] || object(t, "notes", text)["next"] != fmt.Sprint(ids[1]) {
		t.Fatalf("list_notifications with numbers: %s", text)
	}
	// over stdio, as a client writes it
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_findings","arguments":{"engagement":"acme","limit":7,"cursor":7}}}` + "\n")
	var out bytes.Buffer
	if err := f.s.ServeStdio(context.Background(), alice, in, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "isError") || strings.Count(out.String(), `\"dir\"`) != 3 {
		t.Fatalf("stdio: %.400s", out.String())
	}
	// what tools/list and the catalogue say
	props := listedTools(f)["list_findings"]["inputSchema"].(map[string]any)["properties"].(map[string]any)
	if props["limit"].(map[string]any)["type"] != "integer" || props["cursor"].(map[string]any)["type"] != "string" || props["q"].(map[string]any)["type"] != "string" {
		t.Errorf("schema: limit %v, cursor %v", props["limit"], props["cursor"])
	}
	for _, td := range Catalog() {
		for _, p := range td.Params {
			if want := map[string]string{"limit": "integer"}[p.Name]; want != "" && p.Type != want {
				t.Errorf("%s %s: catalogue type %q", td.Name, p.Name, p.Type)
			}
		}
	}
}

// hint is a tool's annotations: readOnlyHint, destructiveHint,
// openWorldHint.
type hint struct{ readOnly, destructive, openWorld bool }

// wantHints is what each tool does, set by hand: a hint is what a client
// may skip a confirmation for.
var wantHints = map[string]hint{
	"list_engagements": {readOnly: true}, "list_findings": {readOnly: true}, "read_finding": {readOnly: true}, "list_templates": {readOnly: true},
	"get_check_results": {readOnly: true}, "list_notifications": {readOnly: true}, "whoami": {readOnly: true}, "get_config": {readOnly: true},
	"list_team": {readOnly: true}, "read_chat": {readOnly: true}, "list_history": {readOnly: true}, "list_attachments": {readOnly: true},
	"read_template": {readOnly: true},
	// they add, and replace or remove nothing
	"create_finding": {}, "add_chat_message": {}, "resolve_thread": {}, "mark_notifications_read": {},
	// they add too, and send text to the AI provider (lint_finding with
	// all=true starts a check run: not read-only)
	"lint_finding": {openWorld: true}, "start_check": {openWorld: true},
	// they replace what is there
	"update_section": {destructive: true}, "set_field": {destructive: true}, "transition": {destructive: true},
	"fix_checks": {destructive: true, openWorld: true},
}

// pre1 6.5: tools/list gives each tool its annotations, all three said, in
// both workflows; and a tool marked read-only changes nothing: no commit, no
// chat message, no notification read.
func TestToolAnnotations(t *testing.T) {
	for _, f := range []*fx{newFx(t), newSimpleFx(t)} {
		listed := listedTools(f)
		if len(listed) != len(wantHints) {
			t.Fatalf("%d tools listed, %d with hints in the test", len(listed), len(wantHints))
		}
		for name, want := range wantHints {
			an, _ := listed[name]["annotations"].(map[string]any)
			if len(an) != 3 || an["readOnlyHint"] != want.readOnly || an["destructiveHint"] != want.destructive || an["openWorldHint"] != want.openWorld {
				t.Errorf("%s (simple %v): annotations %v, want %+v", name, f.s.flow().Simple, an, want)
			}
		}
	}
	for _, tl := range tools {
		if tl.readOnly && (tl.action != "" || tl.destructive || tl.openWorld) {
			t.Errorf("%s is read-only and needs %q, destructive %v, open %v", tl.name, tl.action, tl.destructive, tl.openWorld)
		}
	}

	f := stateFx(t, "verification")
	withRules(t, f)
	addTemplate(t, f, "sqli", "SQL injection")
	d := f.s.Store.DB()
	d.AddUser(bob)
	d.AddNotification(db.Notification{User: "bob", Event: "review", Eng: "acme", Fid: "F-001", Actor: "alice"})
	f.ok(alice, "add_chat_message", f001("text", "a question"))
	state := func() string {
		t.Helper()
		main, err := exec.Command("git", "-C", f.dir, "log", "-1", "--format=%H").Output()
		if err != nil {
			t.Fatal(err)
		}
		msgs, err := f.s.Store.Chat("acme", "001")
		if err != nil {
			t.Fatal(err)
		}
		unread, err := f.s.Store.NotificationPage(bob, true, nil, 0, 50)
		if err != nil {
			t.Fatal(err)
		}
		st, err := d.State("acme", "F-001")
		if err != nil {
			t.Fatal(err)
		}
		runs, err := f.s.Store.CheckStatus("acme", "001")
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprint(strings.TrimSpace(string(main)), " ", f.lastCommit(), " chat ", len(msgs), " unread ", len(unread), " state ", st, " run ", runs.HasRun)
	}
	before := state()
	fd := f001()
	args := map[string]map[string]any{"list_engagements": {}, "list_findings": {"engagement": "acme"}, "read_finding": fd, "list_templates": {},
		"get_check_results": fd, "list_notifications": {}, "whoami": {}, "get_config": {}, "list_team": {"engagement": "acme"}, "read_chat": fd,
		"list_history": fd, "list_attachments": fd, "read_template": {"template": "sqli"}}
	for name, want := range wantHints {
		if !want.readOnly {
			continue
		}
		a, ok := args[name]
		if !ok {
			t.Fatalf("%s: the test has no call for it", name)
		}
		if text, isErr := f.call(bob, name, a); isErr {
			t.Fatalf("%s: %s", name, text)
		}
		if after := state(); after != before {
			t.Errorf("%s is marked read-only and changed something:\n%s\n%s", name, before, after)
		}
	}
}
