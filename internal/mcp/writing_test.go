package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/rules"
	"yars/internal/store"
)

func TestMarkNotificationsRead(t *testing.T) {
	f := newFx(t)
	d := f.s.Store.DB()
	d.AddUser(alice)
	d.AddUser(bob)
	var ids []int64
	for i := range 3 {
		id, _ := d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "acme", Fid: "F-001", Actor: "bob", Text: fmt.Sprint(i)})
		ids = append(ids, id)
	}
	bobs, _ := d.AddNotification(db.Notification{User: "bob", Event: "review", Eng: "acme", Fid: "F-001"})
	unread := func(u config.User) int {
		var l []any
		itemsOf(t, f.ok(u, "list_notifications", map[string]any{"unread": true}), &l)
		return len(l)
	}
	if m := message(t, f.ok(alice, "mark_notifications_read", map[string]any{"ids": fmt.Sprintf("%d, %d", ids[0], ids[1])})); m != "marked 2 read" || unread(alice) != 1 {
		t.Fatalf("%s, %d unread", m, unread(alice))
	}
	for _, c := range []struct {
		args map[string]any
		code string
	}{
		{map[string]any{"ids": "x"}, "invalid"},
		{map[string]any{}, "invalid"},
		{map[string]any{"ids": fmt.Sprint(ids[2]), "all": true}, "invalid"},
		{map[string]any{"ids": fmt.Sprint(bobs)}, "not_found"}, // bob's
	} {
		text, isErr := f.call(alice, "mark_notifications_read", c.args)
		if m := object(t, "mark", text); !isErr || m["code"] != c.code {
			t.Errorf("%v: %s", c.args, text)
		}
	}
	if m := message(t, f.ok(alice, "mark_notifications_read", map[string]any{"all": true})); m != "marked all read" || unread(alice) != 0 || unread(bob) != 1 {
		t.Fatalf("%s: alice %d, bob %d unread", m, unread(alice), unread(bob))
	}
}

// A token limited to some engagements marks only their notifications.
func TestMarkReadKeepsToTheToken(t *testing.T) {
	f := newFx(t)
	d := f.s.Store.DB()
	d.AddUser(alice)
	f.s.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, dora.GitAuthor())
	d.AddMembers("beta", "alice")
	a, _ := d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "acme", Fid: "F-001", Actor: "bob"})
	b, _ := d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "beta", Fid: "F-001", Actor: "bob"})
	only := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}, Engagements: []string{"acme"}}
	if text, isErr := f.callTok(alice, only, "mark_notifications_read", map[string]any{"ids": fmt.Sprint(b)}); !isErr || object(t, "b", text)["code"] != "not_found" {
		t.Fatalf("another engagement's: %s", text)
	}
	if text, isErr := f.callTok(alice, only, "mark_notifications_read", map[string]any{"all": true}); isErr {
		t.Fatal(text)
	}
	for id, want := range map[int64]bool{a: true, b: false} {
		if n, _, _ := d.NotificationByID("alice", id); n.Read != want {
			t.Errorf("%d read %v, want %v", id, n.Read, want)
		}
	}
}

// fixer is the rules engine with a Fix that makes every foo bar.
type fixer struct {
	*rules.Engine
	calls int
}

func (x *fixer) Fix(_ context.Context, _ rules.Violation, _, body string) (string, error) {
	x.calls++
	return strings.ReplaceAll(body, "foo", "bar"), nil
}

func (x *fixer) AIConfigured() bool { return true }

func TestFixChecksStarts(t *testing.T) {
	f := newFx(t)
	rd := filepath.Join(f.dir, ".yars", "rules")
	os.MkdirAll(rd, 0o755)
	os.WriteFile(filepath.Join(rd, "r.yaml"), []byte("- id: no-foo\n  target: section:Impact\n  regex_forbid: 'foo'\n  level: warning\n  message: Avoid foo\n"), 0o644)
	eng := rules.NewEngine(rd, f.s.Cfg)
	f.s.Rules, f.s.Store.Linter = eng, eng
	a := map[string]any{"engagement": "acme", "finding": "F-001"}
	f.ok(alice, "update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "a foo here"})
	f.ok(alice, "start_check", a)
	f.s.Store.WaitChecks()
	fx := &fixer{Engine: eng}
	f.s.Store.Linter = fx
	if m := message(t, f.ok(alice, "fix_checks", a)); m != "fix started; read get_check_results" {
		t.Fatalf("%s", m)
	}
	f.s.Store.WaitChecks()
	var rd2 struct {
		Sections []struct{ Name, Body string } `json:"sections"`
	}
	json.Unmarshal([]byte(f.ok(alice, "read_finding", a)), &rd2)
	if fx.calls != 1 || !strings.Contains(rd2.Sections[1].Body+rd2.Sections[0].Body+fmt.Sprint(rd2.Sections), "a bar here") {
		t.Fatalf("%d calls, %+v", fx.calls, rd2.Sections)
	}
	// nothing left to fix: invalid with the store's words
	text, isErr := f.call(alice, "fix_checks", a)
	if m := object(t, "again", text); !isErr || m["code"] != "invalid" || !strings.Contains(m["message"].(string), "run Check first") {
		t.Fatalf("%s", text)
	}
}

// Review focus 4: a read-only token is refused every new writing tool but
// mark_notifications_read (the user's own state); the reading tools work.
func TestNewToolsRespectScopes(t *testing.T) {
	f := newFx(t)
	f.s.Store.DB().AddUser(alice)
	read := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}}
	a := map[string]any{"engagement": "acme", "finding": "F-001"}
	if text, isErr := f.callTok(alice, read, "fix_checks", a); !isErr || object(t, "fix", text)["code"] != "not_allowed" {
		t.Fatalf("fix_checks with a read token: %s", text)
	}
	for tool, args := range map[string]map[string]any{"whoami": {}, "read_chat": a, "get_config": {}, "list_history": a, "mark_notifications_read": {"all": true}} {
		if text, isErr := f.callTok(alice, read, tool, args); isErr {
			t.Errorf("%s with a read token: %s", tool, text)
		}
	}
}

// On a clone (stdio, no database) the server-only tools say so.
func TestServerOnlyToolsOnClone(t *testing.T) {
	clone := cloneOf(t, newFx(t))
	for tool, args := range map[string]map[string]any{
		"fix_checks":              {"engagement": "acme", "finding": "F-001"},
		"mark_notifications_read": {"all": true},
	} {
		text, isErr := clone.call(alice, tool, args)
		if m := object(t, tool, text); !isErr || m["code"] != "no_database" {
			t.Errorf("%s on a clone: %s", tool, text)
		}
	}
}
