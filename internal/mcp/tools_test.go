package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/rules"
	"yars/internal/store"
)

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
	if out, isErr := f.call(alice, "create_finding", map[string]any{"engagement": "acme", "title": "x", "template": "nope"}); !isErr || !strings.HasPrefix(out, `unknown template "nope"`) {
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

// Notifications of engagements alice can't see neither show nor push her
// own off the list.
func TestMCPNotificationsHiddenBeyondLimit(t *testing.T) {
	f := newFx(t)
	d := f.s.Store.DB()
	d.AddUser(alice)
	d.AddNotification(db.Notification{User: "alice", Event: "returned", Eng: "acme", Fid: "F-001", Actor: "bob", Text: "mine"})
	for range 60 {
		d.AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "gone", Fid: "F-001", Actor: "bob", Text: "off the team"})
	}
	for _, a := range []map[string]any{nil, {"unread": true}} {
		if out := f.ok(alice, "list_notifications", a); !strings.Contains(out, "mine") || strings.Contains(out, "off the team") {
			t.Fatalf("%v: %s", a, out)
		}
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

// A disabled account can't be assigned as a reviewer.
func TestMCPDisabledNotReviewer(t *testing.T) {
	f := newFx(t)
	f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": "bob"})
	all := f.s.Users()
	f.s.Users = func() []config.User {
		us := slices.Clone(all)
		for i := range us {
			us[i].Disabled = us[i].Username == "bob"
		}
		return us
	}
	out, isErr := f.call(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": "bob"})
	if !isErr || !strings.Contains(out, "bob") {
		t.Fatalf("assigned a disabled account: %s", out)
	}
}

// lint_finding with all=true runs script and AI rules: it needs "checks".
func TestMCPLintAllNeedsChecks(t *testing.T) {
	f := newFx(t)
	read := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}}
	a := map[string]any{"engagement": "acme", "finding": "F-001"}
	if out, isErr := f.callTok(alice, read, "lint_finding", a); isErr {
		t.Fatalf("fast lint with a read token: %s", out)
	}
	a["all"] = true
	if out, isErr := f.callTok(alice, read, "lint_finding", a); !isErr || !strings.Contains(out, "token") {
		t.Fatalf("lint all=true with a read token: %s", out)
	}
	checks := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{"checks"}}
	if out, isErr := f.callTok(alice, checks, "lint_finding", a); isErr {
		t.Fatalf("lint all=true with checks: %s", out)
	}
}

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

// A CVSS reason edit says so in its commit, not "set CVSS <score>" as if
// the vector had changed.
func TestMCPCVSSReasonCommit(t *testing.T) {
	f := newFx(t)
	set := func(field, value string) {
		f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": field, "value": value})
	}
	set("cvss", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N")
	if got := f.lastCommit(); got != "alice|F-001: set CVSS 5.9" {
		t.Fatalf("vector commit %q", got)
	}
	set("cvss_reason.AC", "needs a race")
	if got := f.lastCommit(); got != "alice|F-001: edit CVSS reason AC" {
		t.Fatalf("reason commit %q", got)
	}
}

// list_notifications gives the finding's current title, as the web does.
func TestMCPNotificationsCurrentTitle(t *testing.T) {
	f := newFx(t)
	f.s.Store.DB().AddUser(alice)
	f.s.Store.DB().AddNotification(db.Notification{User: "alice", Event: "mentioned", Eng: "acme", Fid: "F-001", Title: "old name", Actor: "bob"})
	out := f.ok(alice, "list_notifications", map[string]any{})
	if !strings.Contains(out, `"title": "SQL injection"`) || strings.Contains(out, "old name") {
		t.Fatalf("notifications:\n%s", out)
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
