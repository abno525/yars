package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/rules"
	"yars/internal/store"
)

// addTemplate commits a template to the main repo.
func addTemplate(t *testing.T, f *fx, slug, title string) {
	t.Helper()
	err := f.s.Store.SaveTemplate(slug, gitrepo.Author{Name: "dora", Email: "dora@yars.local"}, func(cur *finding.Finding) (*finding.Finding, error) {
		nf := f.s.Store.NewTemplate(title)
		nf.SetSection("Impact", "Attackers read every row.")
		return nf, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMCPTemplates(t *testing.T) {
	f := newFx(t)
	addTemplate(t, f, "sqli", "SQL injection")
	out := f.ok(alice, "list_templates", nil)
	var ts []struct {
		Slug  string `json:"slug"`
		Title string `json:"title"`
		Uses  int    `json:"uses"`
	}
	if err := json.Unmarshal([]byte(out), &ts); err != nil || len(ts) != 1 || ts[0].Slug != "sqli" || ts[0].Title != "SQL injection" {
		t.Fatalf("%s %v", out, err)
	}
	out = f.ok(alice, "create_finding", map[string]any{"engagement": "acme", "title": "SQLi in search", "template": "sqli"})
	var c struct{ ID, Dir string }
	json.Unmarshal([]byte(out), &c)
	ref, err := f.s.Store.Finding("acme", c.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := ref.F.Section("Impact"); !strings.Contains(body, "Attackers read every row.") || ref.F.Meta.Author != "alice" {
		t.Fatalf("not from the template: %q", body)
	}
	if out, isErr := f.call(alice, "create_finding", map[string]any{"engagement": "acme", "title": "x", "template": "nope"}); !isErr || out != "not found" {
		t.Fatalf("unknown template: %s", out)
	}
	if n := f.ok(alice, "list_templates", nil); !strings.Contains(n, `"uses": 1`) {
		t.Fatalf("uses %s", n)
	}
}

// withdraw, revise and report go through transition; report needs the
// export action on a token, and a director.
func TestMCPWithdrawReviseReport(t *testing.T) {
	f := newFx(t)
	a := map[string]any{"engagement": "acme", "finding": "F-001"}
	with := func(k, v string) map[string]any {
		m := map[string]any{}
		for x, y := range a {
			m[x] = y
		}
		m["action"] = k
		if v != "" {
			m["reason"] = v
		}
		return m
	}
	if out, isErr := f.call(alice, "transition", with("withdraw", "")); !isErr || !strings.Contains(out, "reason") {
		t.Fatalf("withdraw without reason: %s", out)
	}
	if out := f.ok(alice, "transition", with("withdraw", "duplicate of F-002")); !strings.Contains(out, "withdrawn") {
		t.Fatal(out)
	}
	if out := f.ok(alice, "transition", with("revise", "")); !strings.Contains(out, "draft") {
		t.Fatal(out)
	}
	status := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{"status"}}
	if out, isErr := f.callTok(dora, status, "transition", with("report", "")); !isErr || !strings.Contains(out, "token") {
		t.Fatalf("report with a status-only token: %s", out)
	}
	if out, isErr := f.callTok(dora, status, "transition", with("withdraw", "out of scope")); isErr {
		t.Fatalf("withdraw with the status scope: %s", out)
	}
	export := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{"export"}}
	if out, isErr := f.callTok(alice, export, "transition", with("report", "")); !isErr || !strings.Contains(out, "director") {
		t.Fatalf("report by a pentester: %s", out)
	}
}

func TestMCPChecks(t *testing.T) {
	f := newFx(t)
	os.MkdirAll(filepath.Join(f.dir, ".yars", "rules"), 0o755)
	os.WriteFile(filepath.Join(f.dir, ".yars", "rules", "r.yaml"), []byte("- id: no-sql\n  target: title\n  regex_forbid: 'SQL'\n  message: Spell out SQL\n"), 0o644)
	eng := rules.NewEngine(rules.DirFor(f.dir), f.s.Cfg)
	f.s.Store.Linter, f.s.Rules = eng, eng
	a := map[string]any{"engagement": "acme", "finding": "F-001"}
	read := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}}
	if out, isErr := f.callTok(alice, read, "start_check", a); !isErr || !strings.Contains(out, "token") {
		t.Fatalf("start_check with a read token: %s", out)
	}
	if out := f.ok(alice, "get_check_results", a); !strings.Contains(out, `"has_run": false`) {
		t.Fatalf("before %s", out)
	}
	out := f.ok(alice, "start_check", a)
	if !strings.Contains(out, `"run_id"`) {
		t.Fatal(out)
	}
	f.s.Store.WaitChecks()
	out = f.ok(alice, "get_check_results", a)
	var st struct {
		HasRun  bool   `json:"has_run"`
		State   string `json:"state"`
		Stale   bool   `json:"stale"`
		Results []struct {
			Rule, Level, Message string
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out), &st); err != nil || !st.HasRun || st.State != "done" || len(st.Results) != 1 || st.Results[0].Rule != "no-sql" {
		t.Fatalf("%s %v", out, err)
	}
	// archived: no new run, results still readable
	f.s.Store.Archive("acme", dora)
	if out, isErr := f.call(alice, "start_check", a); !isErr || !strings.Contains(out, "archived") {
		t.Fatalf("archived %s", out)
	}
	f.ok(alice, "get_check_results", a)
}

func TestMCPNotifications(t *testing.T) {
	f := newFx(t)
	d := f.s.Store.DB()
	for _, u := range []config.User{alice, bob} {
		d.AddUser(u)
	}
	f.s.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, dora.GitAuthor())
	d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "gone", Fid: "F-009", Actor: "bob", Text: "off the team"})
	d.AddMembers("beta", "alice")
	d.AddNotification(db.Notification{User: "alice", Event: "returned", Eng: "acme", Fid: "F-001", Actor: "bob", Text: "add a PoC"})
	d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "beta", Fid: "F-001", Actor: "bob"})
	id, _ := d.AddNotification(db.Notification{User: "bob", Event: "review", Eng: "acme", Fid: "F-001"})
	d.MarkRead("bob", id)
	out := f.ok(alice, "list_notifications", nil)
	if !strings.Contains(out, "add a PoC") || !strings.Contains(out, `"event": "mentioned"`) || strings.Contains(out, `"review"`) || strings.Contains(out, "off the team") {
		t.Fatalf("%s", out)
	}
	// a token limited to acme sees only acme's
	only := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}, Engagements: []string{"acme"}}
	if out, _ := f.callTok(alice, only, "list_notifications", nil); strings.Contains(out, "beta") || !strings.Contains(out, "acme") {
		t.Fatalf("token engagements %s", out)
	}
	if out := f.ok(bob, "list_notifications", map[string]any{"unread": true}); out != "[]" {
		t.Fatalf("unread %s", out)
	}
}

// unread: true finds an unread notification behind 50 newer read ones.
func TestMCPUnreadNotificationsBeyondLimit(t *testing.T) {
	f := newFx(t)
	d := f.s.Store.DB()
	d.AddUser(alice)
	d.AddNotification(db.Notification{User: "alice", Event: "returned", Eng: "acme", Fid: "F-001", Actor: "bob", Text: "old but unread"})
	for range 60 {
		id, _ := d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "acme", Fid: "F-001", Actor: "bob", Text: "seen"})
		d.MarkRead("alice", id)
	}
	if out := f.ok(alice, "list_notifications", map[string]any{"unread": true}); !strings.Contains(out, "old but unread") || strings.Contains(out, "seen") {
		t.Fatalf("unread %s", out)
	}
}

// Every tool is documented in docs/mcp.md, and the catalogue the web page
// shows lists them all with their parameters.
func TestToolCatalog(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", "mcp.md"))
	if err != nil {
		t.Fatal(err)
	}
	cat := Catalog()
	if len(cat) != len(tools) {
		t.Fatalf("%d of %d", len(cat), len(tools))
	}
	for _, td := range cat {
		if !strings.Contains(string(b), "`"+td.Name+"`") {
			t.Errorf("docs/mcp.md lacks %s", td.Name)
		}
	}
	i := -1
	for k, td := range cat {
		if td.Name == "update_section" {
			i = k
		}
	}
	u := cat[i]
	if u.Action != "edit" || u.ServerOnly || len(u.Params) != 5 || !u.Params[0].Required || u.Params[4].Name != "base" || u.Params[4].Required || u.Params[0].Type != "string" {
		t.Fatalf("%+v", u)
	}
	for _, td := range cat {
		if td.Name == "transition" && !td.ServerOnly {
			t.Error("transition runs on the server only")
		}
		if td.Name == "lint_finding" && td.Params[2].Type != "boolean" {
			t.Error("all is a boolean")
		}
	}
}
