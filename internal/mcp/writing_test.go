package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/store"
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

// add_chat_message says which @names got no notice: an unknown name, a
// disabled account and one off the team read the same, as plain names
// beside the id. When everyone is told the key is left out.
func TestChatSaysWhoIsNotNotified(t *testing.T) {
	f := newFx(t)
	d := f.s.Store.DB()
	for _, u := range []config.User{alice, bob, {Username: "out", Role: "pentester"}, {Username: "gone", Role: "pentester"}} {
		if err := d.AddUser(u); err != nil {
			t.Fatal(err)
		}
	}
	d.SetDisabled("gone", true)
	d.AddMembers("acme", "gone")
	text, _ := f.wire(bob, "add_chat_message", map[string]any{"engagement": "acme", "finding": "F-001", "text": "@alice @out @gone @nobody @bob which roles?"})
	var got struct {
		OK          bool     `json:"ok"`
		ID          string   `json:"id"`
		NotNotified []string `json:"not_notified"`
		Untrusted   any      `json:"untrusted"`
	}
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatal(err)
	}
	if !got.OK || got.ID == "" || strings.Join(got.NotNotified, ",") != "out,gone,nobody" || got.Untrusted != nil {
		t.Fatalf("answer %s", text)
	}
	text, _ = f.wire(bob, "add_chat_message", map[string]any{"engagement": "acme", "finding": "F-001", "text": "@alice thanks"})
	if strings.Contains(text, "not_notified") {
		t.Fatalf("a key although everyone is told: %s", text)
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
	impact := ""
	for _, s := range rd2.Sections {
		if s.Name == "Impact" {
			impact = strings.TrimSpace(s.Body)
		}
	}
	if fx.calls != 1 || impact != "a bar here" {
		t.Fatalf("%d calls, Impact %q", fx.calls, impact)
	}
	// the AI's answer is in the check's thread, marked
	var chat []struct {
		Replies []struct {
			Text string
			AI   bool
		}
	}
	itemsOf(t, f.ok(alice, "read_chat", a), &chat)
	if len(chat) != 1 || len(chat[0].Replies) != 1 || chat[0].Replies[0].Text != "Fixed." || !chat[0].Replies[0].AI {
		t.Fatalf("chat %+v", chat)
	}
	// nothing left to fix: invalid with the store's words (no "invalid
	// value:" in front, as the website shows them)
	text, isErr := f.call(alice, "fix_checks", a)
	if m := object(t, "again", text); !isErr || m["code"] != "invalid" || m["message"] != "nothing to fix: run Check first" {
		t.Fatalf("%s", text)
	}
}

// fix_checks keeps the website's refusals: a fix or check running (busy),
// an approved finding (not_allowed), an archived engagement.
func TestFixChecksRefusals(t *testing.T) {
	f := newFx(t)
	a := map[string]any{"engagement": "acme", "finding": "F-001"}
	f.s.Rules = rules.NewEngine(t.TempDir(), f.s.Cfg)
	f.s.Store.Linter = &fixer{Engine: f.s.Rules}
	if err := f.s.Store.DB().Tx(func(tx *db.Tx) error {
		return tx.PutState("acme", "F-001", db.State{Status: "complete"})
	}); err != nil {
		t.Fatal(err)
	}
	if text, isErr := f.call(dora, "fix_checks", a); !isErr || object(t, "complete", text)["code"] != "not_allowed" {
		t.Errorf("an approved finding: %s", text)
	}
	f.s.Store.DB().Tx(func(tx *db.Tx) error { return tx.PutState("acme", "F-001", db.State{Status: "draft"}) })
	f.s.Store.Archive("acme", dora)
	if text, isErr := f.call(alice, "fix_checks", a); !isErr || object(t, "archived", text)["code"] != "archived" {
		t.Errorf("archived: %s", text)
	}
}

// fix_checks rewrites text: a token needs edit as well as checks.
func TestFixChecksNeedsEdit(t *testing.T) {
	f := newFx(t)
	checks := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead, "checks"}}
	text, isErr := f.callTok(alice, checks, "fix_checks", map[string]any{"engagement": "acme", "finding": "F-001"})
	if m := object(t, "fix", text); !isErr || m["code"] != "not_allowed" || !strings.Contains(m["message"].(string), "edit findings") {
		t.Fatalf("checks without edit: %s", text)
	}
}

// read_finding's can_edit follows the token too: a read-only token may not
// edit, whatever the account may.
func TestCanEditFollowsToken(t *testing.T) {
	f := newFx(t)
	a := map[string]any{"engagement": "acme", "finding": "F-001"}
	read := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}}
	text, _ := f.callTok(alice, read, "read_finding", a)
	if object(t, "read", text)["can_edit"] != false {
		t.Fatalf("read token: can_edit true")
	}
	edit := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead, "edit"}}
	text, _ = f.callTok(alice, edit, "read_finding", a)
	if object(t, "edit", text)["can_edit"] != true {
		t.Fatalf("edit token: can_edit false")
	}
}

// Without a reason on a clone or an archived engagement the real refusal
// comes first (as allowed_actions lists it), not "a reason is required".
func TestTransitionNoReasonRealRefusalFirst(t *testing.T) {
	a := map[string]any{"engagement": "acme", "finding": "F-001", "action": "withdraw"}
	f := newFx(t)
	if text, _ := cloneOf(t, f).call(alice, "transition", a); object(t, "clone", text)["code"] != "no_database" {
		t.Errorf("clone: %s", text)
	}
	f.s.Store.Archive("acme", dora)
	if text, _ := f.call(alice, "transition", a); object(t, "archived", text)["code"] != "archived" {
		t.Errorf("archived: %s", text)
	}
}

// ids are at most 200, each once; the answer counts what was asked.
func TestMarkReadIDs(t *testing.T) {
	f := newFx(t)
	d := f.s.Store.DB()
	d.AddUser(alice)
	id, _ := d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "acme", Fid: "F-001", Actor: "bob"})
	if m := message(t, f.ok(alice, "mark_notifications_read", map[string]any{"ids": fmt.Sprintf("%d,%d", id, id)})); m != "marked 1 read" {
		t.Fatalf("%s", m)
	}
	many := strings.TrimSuffix(strings.Repeat(fmt.Sprint(id)+",", 201), ",")
	if text, isErr := f.call(alice, "mark_notifications_read", map[string]any{"ids": many}); isErr {
		t.Fatalf("201 copies of one id: %s", text) // one id, once
	}
	var lots []string
	for i := range 201 {
		lots = append(lots, fmt.Sprint(int(id)+i))
	}
	text, isErr := f.call(alice, "mark_notifications_read", map[string]any{"ids": strings.Join(lots, ",")})
	if m := object(t, "lots", text); !isErr || m["code"] != "invalid" || !strings.Contains(m["message"].(string), "200") {
		t.Fatalf("201 ids: %s", text)
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
