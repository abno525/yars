package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/store"
)

// callTok invokes a tool as u holding token tk.
func (f *fx) callTok(u config.User, tk db.TokenInfo, tool string, args map[string]any) (string, bool) {
	f.t.Helper()
	f.id++
	args = f.signed(tool, args)
	msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": f.id, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args}})
	var resp struct {
		Result struct {
			Content []struct{ Text string }
			IsError bool
		}
	}
	out := f.s.Handle(WithToken(context.Background(), tk), u, msg)
	if err := json.Unmarshal(out, &resp); err != nil {
		f.t.Fatal(err)
	}
	return resp.Result.Content[0].Text, resp.Result.IsError
}

func engIDs(t *testing.T, out string) string {
	t.Helper()
	var es []struct {
		ID       string `json:"id"`
		Archived bool   `json:"archived"`
	}
	itemsOf(t, out, &es)
	var ids []string
	for _, e := range es {
		id := e.ID
		if e.Archived {
			id += "(archived)"
		}
		ids = append(ids, id)
	}
	return strings.Join(ids, ",")
}

func TestMCPTeamVisibility(t *testing.T) {
	f := newFx(t)
	f.s.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, dora.GitAuthor())
	if got := engIDs(t, f.ok(alice, "list_engagements", nil)); got != "acme" {
		t.Fatalf("alice sees %s", got)
	}
	if got := engIDs(t, f.ok(dora, "list_engagements", nil)); got != "acme,beta" {
		t.Fatalf("dora sees %s", got)
	}
	for _, tool := range []string{"list_findings", "create_finding", "read_finding"} {
		out, isErr := f.call(alice, tool, map[string]any{"engagement": "beta", "finding": "F-001", "title": "x"})
		if !isErr || message(t, out) != "not found" {
			t.Errorf("%s on another team's engagement: %s", tool, out)
		}
	}
}

func TestMCPArchivedRefusesWrites(t *testing.T) {
	f := newFx(t)
	if err := f.s.Store.Archive("acme", dora); err != nil {
		t.Fatal(err)
	}
	if got := engIDs(t, f.ok(alice, "list_engagements", nil)); got != "acme(archived)" {
		t.Fatalf("list %s", got)
	}
	f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})
	f.ok(alice, "list_findings", map[string]any{"engagement": "acme"})
	writes := map[string]map[string]any{
		"update_section":   {"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "x"},
		"create_finding":   {"engagement": "acme", "title": "New"},
		"add_chat_message": {"engagement": "acme", "finding": "F-001", "text": "hi"},
		"set_field":        {"engagement": "acme", "finding": "F-001", "field": "severity", "value": "low"},
		"transition":       {"engagement": "acme", "finding": "F-001", "action": "submit"},
	}
	for tool, a := range writes {
		out, isErr := f.call(alice, tool, a)
		if !isErr || !strings.Contains(out, "archived") {
			t.Errorf("%s on an archived engagement: %s", tool, out)
		}
	}
}

func TestMCPTokenScopes(t *testing.T) {
	f := newFx(t)
	read := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}}
	f.callTok(alice, read, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})
	if _, isErr := f.callTok(alice, read, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"}); isErr {
		t.Fatal("read token can't read")
	}
	out, isErr := f.callTok(alice, read, "update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "x"})
	if !isErr || !strings.Contains(out, "token") {
		t.Fatalf("read token edited: %s", out)
	}
	// selected actions: chat yes, status no, reviewers only with "reviewers"
	some := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{"comment", "edit"}}
	if out, isErr := f.callTok(alice, some, "add_chat_message", map[string]any{"engagement": "acme", "finding": "F-001", "text": "hi"}); isErr {
		t.Fatalf("comment denied: %s", out)
	}
	if _, isErr := f.callTok(alice, some, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": "submit"}); !isErr {
		t.Fatal("status change without the scope")
	}
	if out, isErr := f.callTok(alice, some, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": "bob"}); !isErr || !strings.Contains(out, "token") {
		t.Fatalf("reviewers without the scope: %s", out)
	}
	if out, isErr := f.callTok(alice, some, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "severity", "value": "low"}); isErr {
		t.Fatalf("edit denied: %s", out)
	}
	if _, isErr := f.callTok(alice, some, "create_finding", map[string]any{"engagement": "acme", "title": "x"}); !isErr {
		t.Fatal("create without the scope")
	}
}

// Marking reported needs "export" however the action is spelled.
func TestMCPReportNeedsExportScope(t *testing.T) {
	f := newFx(t)
	status := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{"status"}}
	for _, act := range []string{"report", "Report", " report", "REPORT"} {
		out, isErr := f.callTok(dora, status, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": act})
		if !isErr || !strings.Contains(out, "token") {
			t.Errorf("action %q without the export scope: %s", act, out)
		}
	}
}

// Reviewers must be on the engagement's team.
func TestMCPReviewerOnTeam(t *testing.T) {
	f := newFx(t)
	if err := f.s.Store.DB().RemoveMember("acme", "bob"); err != nil {
		t.Fatal(err)
	}
	out, isErr := f.call(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": "bob"})
	if !isErr || !strings.Contains(out, "bob") {
		t.Fatalf("assigned a reviewer off the team: %s", out)
	}
	f.s.Store.DB().AddMembers("acme", "bob")
	f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": "bob"})
}

func TestMCPTokenEngagements(t *testing.T) {
	f := newFx(t)
	f.s.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, dora.GitAuthor())
	only := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeAll}, Engagements: []string{"beta"}}
	out, isErr := f.callTok(dora, only, "list_engagements", nil)
	if isErr || engIDs(t, out) != "beta" {
		t.Fatalf("list %s", out)
	}
	if out, isErr := f.callTok(dora, only, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"}); !isErr || !strings.Contains(out, "token") {
		t.Fatalf("read outside the token's engagements: %s", out)
	}
}

// Over HTTP: a read-only token is denied update_section; a git token is
// not accepted; an expired one neither; a disabled account's tokens stop.
func TestMCPHTTPScopedToken(t *testing.T) {
	f := newFx(t)
	srv, tk, _ := f.httpServer(t)
	readTok, _, err := tk.Create("bob", "bob", db.TokenSpec{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}})
	if err != nil {
		t.Fatal(err)
	}
	upd := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"update_section","arguments":{"engagement":"acme","finding":"F-001","section":"Impact","body":"x"}}}`
	c, body := post(t, srv.URL, readTok, upd)
	if c != 200 || !strings.Contains(body, `"isError":true`) || !strings.Contains(body, "token") {
		t.Fatalf("%d %s", c, body)
	}
	gitTok, _, _ := tk.Create("bob", "bob", db.TokenSpec{Kind: db.TokenGit, Scopes: []string{db.ScopeAll}})
	if c, _ := post(t, srv.URL, gitTok, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); c != 401 {
		t.Fatalf("git token on /mcp: %d", c)
	}
	old, _, _ := tk.Create("bob", "bob", db.TokenSpec{Kind: db.TokenMCP, Scopes: []string{db.ScopeAll},
		Expires: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)})
	if c, _ := post(t, srv.URL, old, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); c != 401 {
		t.Fatalf("expired token: %d", c)
	}
	f.s.Store.DB().SetDisabled("bob", true)
	if c, _ := post(t, srv.URL, readTok, `{"jsonrpc":"2.0","id":1,"method":"ping"}`); c != 401 {
		t.Fatalf("disabled account's token: %d", c)
	}
}
