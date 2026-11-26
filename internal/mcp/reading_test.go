package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

func TestWhoami(t *testing.T) {
	f := newFx(t)
	m := object(t, "whoami", f.ok(alice, "whoami", nil))
	if m["username"] != "alice" || m["role"] != "pentester" || m["admin"] != false || m["token"] != nil {
		t.Fatalf("%v", m)
	}
	tok := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{"read", "comment"}, Engagements: []string{"acme"}}
	text, _ := f.callTok(dora, tok, "whoami", nil)
	m = object(t, "whoami", text)
	tk, _ := m["token"].(map[string]any)
	if m["username"] != "dora" || m["role"] != "director" || tk == nil || fmt.Sprint(tk["scopes"]) != "[read comment]" || fmt.Sprint(tk["engagements"]) != "[acme]" {
		t.Fatalf("%v", m)
	}
}

func TestGetConfig(t *testing.T) {
	f := newFx(t)
	var c struct {
		Sections    []string          `json:"sections"`
		DetailsRows []string          `json:"details_rows"`
		Severities  []string          `json:"severities"`
		CVSSVersion string            `json:"cvss_version"`
		Standard    map[string]string `json:"cvss_standard"`
		Statuses    []string          `json:"statuses"`
		Actions     []string          `json:"actions"`
	}
	if err := json.Unmarshal([]byte(f.ok(alice, "get_config", nil)), &c); err != nil {
		t.Fatal(err)
	}
	cfg := f.s.Store.Config()
	if !slices.Equal(c.Sections, cfg.Sections) || !slices.Equal(c.DetailsRows, cfg.DetailsRows) || !slices.Equal(c.Severities, cfg.Severities) ||
		c.CVSSVersion != cfg.CVSS.Version || c.Standard["AV"] != cfg.CVSS.Standard["AV"] || !slices.Equal(c.Statuses, workflow.AllStatuses) || !slices.Contains(c.Actions, "take_back") || !slices.Contains(c.Actions, "revert") {
		t.Fatalf("%+v", c)
	}
}

func TestListTeam(t *testing.T) {
	f := newFx(t)
	var team []struct {
		Username, Role string
	}
	itemsOf(t, f.ok(alice, "list_team", map[string]any{"engagement": "acme"}), &team)
	got := fmt.Sprint(team)
	if got != "[{alice pentester} {bob reviewer} {pen2 pentester}]" {
		t.Fatalf("%s", got)
	}
}

// read_finding gives each section's text and every action of the status
// with whether the caller may take it now.
func TestReadFindingHasBodiesAndActions(t *testing.T) {
	f := newFx(t)
	f.ok(alice, "update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "Full read."})
	var rd struct {
		Sections []struct{ Name, Base, Body string } `json:"sections"`
		Allowed  []workflow.Allowed                  `json:"allowed_actions"`
	}
	json.Unmarshal([]byte(f.ok(alice, "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})), &rd)
	i := slices.IndexFunc(rd.Sections, func(s struct{ Name, Base, Body string }) bool { return s.Name == "Impact" })
	if i < 0 || strings.TrimSpace(rd.Sections[i].Body) != "Full read." || rd.Sections[i].Base == "" {
		t.Fatalf("sections %+v", rd.Sections)
	}
	acts := map[string]workflow.Allowed{}
	for _, a := range rd.Allowed {
		acts[a.Action] = a
	}
	if s := acts["submit"]; s.Enabled || !strings.Contains(s.Reason, "assign at least one reviewer") {
		t.Fatalf("submit %+v", s)
	}
	if w := acts["withdraw"]; !w.Enabled || w.Needs != "reason" {
		t.Fatalf("withdraw %+v", w)
	}
	if _, ok := acts["approve"]; ok {
		t.Fatalf("approve listed for a draft: %+v", rd.Allowed)
	}
}

// stateFx is a fixture whose F-001 is in state: draft (not ready), ready
// (reviewer bob, severity high), verification, cleared (bob signed off),
// complete, reported, withdrawn.
func stateFx(t *testing.T, state string) *fx {
	t.Helper()
	f := newFx(t)
	a := map[string]any{"engagement": "acme", "finding": "F-001"}
	set := func(field, value string) {
		f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": field, "value": value})
	}
	tr := func(u config.User, act string) {
		m := map[string]any{"action": act, "reason": "because"}
		for k, v := range a {
			m[k] = v
		}
		f.ok(u, "transition", m)
	}
	if state == "draft" {
		return f
	}
	set("reviewers", "bob")
	set("severity", "high")
	steps := map[string][]func(){
		"ready":        nil,
		"verification": {func() { tr(alice, "submit") }},
		"cleared":      {func() { tr(alice, "submit") }, func() { tr(bob, "clear") }},
		"complete":     {func() { tr(alice, "submit") }, func() { tr(bob, "clear") }, func() { tr(dora, "approve") }},
		"reported":     {func() { tr(alice, "submit") }, func() { tr(bob, "clear") }, func() { tr(dora, "approve") }, func() { tr(dora, "report") }},
		"withdrawn":    {func() { tr(alice, "withdraw") }},
	}
	for _, step := range steps[state] {
		step()
	}
	return f
}

// cloneOf is a server on f's folder without the database (yars mcp on a
// clone).
func cloneOf(t *testing.T, f *fx) *fx {
	t.Helper()
	r, err := gitrepo.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(r, config.Default(), nil)
	return &fx{t: t, dir: f.dir, s: &Server{Store: st, Index: index.New(st, r), Cfg: config.Default()}}
}

// matchMode is how a state is looked at: as it is, with style rules (an
// error on the title, a warning on Impact; Require Check on), archived,
// through a token, or on a clone.
type matchMode struct {
	name string
	prep func(t *testing.T, f *fx) *fx
	tok  *db.TokenInfo
}

var matchModes = []matchMode{
	{name: "plain", prep: func(_ *testing.T, f *fx) *fx { return f }},
	{name: "rules", prep: func(t *testing.T, f *fx) *fx { withRules(t, f); return f }},
	{name: "archived", prep: func(t *testing.T, f *fx) *fx {
		if err := f.s.Store.Archive("acme", dora); err != nil {
			t.Fatal(err)
		}
		return f
	}},
	{name: "read token", prep: func(_ *testing.T, f *fx) *fx { return f }, tok: &db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}}},
	{name: "status token", prep: func(_ *testing.T, f *fx) *fx { return f }, tok: &db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{"status"}}},
	{name: "clone", prep: cloneOf},
}

// Review focus 3: each action read_finding lists as enabled goes through
// transition; each one listed as disabled is refused with its reason.
func TestAllowedActionsMatchTransition(t *testing.T) {
	for _, mode := range matchModes {
		states := []string{"draft", "ready", "verification", "cleared", "complete", "reported", "withdrawn"}
		users := []config.User{alice, pen2, bob, dora}
		if mode.name != "plain" {
			states, users = []string{"ready", "verification", "cleared", "complete"}, []config.User{alice, bob, dora}
		}
		for _, state := range states {
			for _, u := range users {
				call := func(f *fx, tool string, a map[string]any) (string, bool) {
					if mode.tok != nil {
						return f.callTok(u, *mode.tok, tool, a)
					}
					return f.call(u, tool, a)
				}
				var rd struct {
					Allowed []workflow.Allowed `json:"allowed_actions"`
				}
				text, isErr := call(mode.prep(t, stateFx(t, state)), "read_finding", map[string]any{"engagement": "acme", "finding": "F-001"})
				if isErr {
					t.Fatalf("%s %s/%s: %s", mode.name, state, u.Username, text)
				}
				json.Unmarshal([]byte(text), &rd)
				if len(rd.Allowed) == 0 {
					t.Fatalf("%s %s/%s: no actions", mode.name, state, u.Username)
				}
				for _, al := range rd.Allowed {
					f := mode.prep(t, stateFx(t, state))
					text, isErr := call(f, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": al.Action, "reason": "because"})
					switch {
					case al.Enabled && isErr:
						t.Errorf("%s %s/%s %s listed enabled, refused: %s", mode.name, state, u.Username, al.Action, text)
					case !al.Enabled && !isErr:
						t.Errorf("%s %s/%s %s listed disabled (%s), done", mode.name, state, u.Username, al.Action, al.Reason)
					case !al.Enabled && (al.Reason == "" || !strings.Contains(message(t, text), al.Reason)):
						t.Errorf("%s %s/%s %s: listed %q, refused %q", mode.name, state, u.Username, al.Action, al.Reason, message(t, text))
					}
					// without the reason it needs: a disabled action is refused
					// for the listed reason first, an enabled one asks for it
					if al.Needs != "reason" {
						continue
					}
					text, _ = call(mode.prep(t, stateFx(t, state)), "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": al.Action})
					m := object(t, al.Action, text)
					switch {
					case al.Enabled && m["code"] != "invalid":
						t.Errorf("%s %s/%s %s without a reason: %s", mode.name, state, u.Username, al.Action, text)
					case !al.Enabled && !strings.Contains(m["message"].(string), al.Reason):
						t.Errorf("%s %s/%s %s without a reason: listed %q, refused %s", mode.name, state, u.Username, al.Action, al.Reason, text)
					}
				}
			}
		}
	}
}

// On a clone the chat is the server's: read_chat says so instead of an
// empty list; list_attachments leaves out whether an earlier version is in
// the history (the server's database knows it).
func TestReadingToolsOnClone(t *testing.T) {
	f := newFx(t)
	if _, err := f.s.Store.AddAttachment("acme", "F-001-sql-injection", "notes.txt", []byte("hello"), alice); err != nil {
		t.Fatal(err)
	}
	c := cloneOf(t, f)
	text, isErr := c.call(alice, "read_chat", map[string]any{"engagement": "acme", "finding": "F-001"})
	if !isErr || object(t, "read_chat", text)["code"] != "no_database" {
		t.Fatalf("read_chat on a clone: %s", text)
	}
	text = c.ok(alice, "list_attachments", map[string]any{"engagement": "acme", "finding": "F-001"})
	if strings.Contains(text, "earlier_version_in_history") || !strings.Contains(text, "notes.txt") {
		t.Fatalf("list_attachments on a clone: %s", text)
	}
}

// On a clone a commit made outside yars mcp (a pull, a hand commit) shows
// in list_history at once.
func TestListHistoryOnCloneSeesOutsideCommits(t *testing.T) {
	f := newFx(t)
	c := cloneOf(t, f)
	a := map[string]any{"engagement": "acme", "finding": "F-001"}
	var before, after []any
	itemsOf(t, c.ok(alice, "list_history", a), &before)
	ed := filepath.Join(f.dir, "engagements", "acme")
	p := filepath.Join(ed, "findings", "F-001-sql-injection", "finding.md")
	b, _ := os.ReadFile(p)
	os.WriteFile(p, append(b, []byte("\nmore\n")...), 0o644)
	for _, cmd := range [][]string{{"add", "-A"}, {"-c", "user.name=alice", "-c", "user.email=a@a", "commit", "-qm", "by hand"}} {
		if out, err := exec.Command("git", append([]string{"-C", ed}, cmd...)...).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	itemsOf(t, c.ok(alice, "list_history", a), &after)
	if len(after) != len(before)+1 {
		t.Fatalf("%d versions, then %d", len(before), len(after))
	}
}

// list_team on an engagement that does not exist is not_found, for a
// director too (who sees every engagement).
func TestListTeamUnknownEngagement(t *testing.T) {
	f := newFx(t)
	text, isErr := f.call(dora, "list_team", map[string]any{"engagement": "nope"})
	if !isErr || object(t, "list_team", text)["code"] != "not_found" {
		t.Fatalf("%s", text)
	}
}

// The whole chat, oldest first, a page at a time: threads with their
// replies (an AI reply marked) and workflow events.
func TestReadChatPagedOldestFirst(t *testing.T) {
	f := newFx(t)
	a := map[string]any{"engagement": "acme", "finding": "F-001"}
	with := func(k, v string) map[string]any {
		m := map[string]any{k: v}
		for x, y := range a {
			m[x] = y
		}
		return m
	}
	first := object(t, "first", f.ok(alice, "add_chat_message", with("text", "first")))["id"].(string)
	f.ok(bob, "add_chat_message", map[string]any{"engagement": "acme", "finding": "F-001", "text": "a reply", "reply": first})
	f.ok(bob, "add_chat_message", with("text", "second"))
	f.s.Store.DB().TxFor("acme", func(tx *db.Tx) error {
		return tx.AddMessage("acme", "F-001", chat.Message{ID: chat.NewID(), User: "alice", Kind: chat.KindAI, Reply: first, Text: "Fixed."})
	})
	f.ok(alice, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": "withdraw", "reason": "duplicate"})
	type msg struct {
		User, Text string
		AI         bool
	}
	var items []struct {
		Type    string `json:"type"`
		ID      string `json:"id"`
		User    string `json:"user"`
		Text    string `json:"text"`
		Event   string `json:"event"`
		Replies []msg  `json:"replies"`
	}
	text := f.ok(alice, "read_chat", a)
	itemsOf(t, text, &items)
	if len(items) != 3 || items[0].Text != "first" || items[1].Text != "second" || items[2].Type != "event" || items[2].Event != "withdraw" {
		t.Fatalf("%s", text)
	}
	if r := items[0].Replies; len(r) != 2 || r[0].Text != "a reply" || r[0].AI || r[1].Text != "Fixed." || !r[1].AI {
		t.Fatalf("replies %+v", r)
	}
	var page []any
	p := f.ok(alice, "read_chat", with("limit", "2"))
	itemsOf(t, p, &page)
	if len(page) != 2 || object(t, "page", p)["next"] != "2" {
		t.Fatalf("page %s", p)
	}
}

// The versions, newest first: commit, who (the AI marked), when, what changed.
func TestListHistory(t *testing.T) {
	f := newFx(t)
	f.ok(alice, "update_section", map[string]any{"engagement": "acme", "finding": "F-001", "section": "Impact", "body": "Full read."})
	f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "severity", "value": "high"})
	var vs []struct {
		Commit, Author, Time string
		AI                   bool
		Changed              []string
	}
	text := f.ok(alice, "list_history", map[string]any{"engagement": "acme", "finding": "F-001"})
	itemsOf(t, text, &vs)
	if len(vs) != 3 || fmt.Sprint(vs[0].Changed) != "[severity]" || fmt.Sprint(vs[1].Changed) != "[Impact]" || fmt.Sprint(vs[2].Changed) != "[created]" || vs[1].Author != "alice" || len(vs[0].Commit) != 40 || vs[0].Time == "" {
		t.Fatalf("%s", text)
	}
}

func TestListAttachments(t *testing.T) {
	f := newFx(t)
	if _, err := f.s.Store.AddAttachment("acme", "F-001-sql-injection", "notes.txt", []byte("hello\nthere"), alice); err != nil {
		t.Fatal(err)
	}
	var as []struct {
		Name, Type string
		Size       int64
		InHistory  bool `json:"earlier_version_in_history"`
	}
	text := f.ok(alice, "list_attachments", map[string]any{"engagement": "acme", "finding": "F-001"})
	itemsOf(t, text, &as)
	if len(as) != 1 || as[0].Name != "notes.txt" || as[0].Size != 11 || as[0].Type != "file" || as[0].InHistory {
		t.Fatalf("%s", text)
	}
}

func TestReadTemplateUnknownIsNotFound(t *testing.T) {
	f := newFx(t)
	addTemplate(t, f, "sqli", "SQL injection")
	m := object(t, "read_template", f.ok(alice, "read_template", map[string]any{"template": "sqli"}))
	if m["slug"] != "sqli" || m["title"] != "SQL injection" || !strings.Contains(m["markdown"].(string), "Attackers read every row.") {
		t.Fatalf("%v", m)
	}
	text, isErr := f.call(alice, "read_template", map[string]any{"template": "nope"})
	if m := object(t, "nope", text); !isErr || m["code"] != "not_found" {
		t.Fatalf("%s", text)
	}
}
