package mcp

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/index"
	"yars/internal/store"
	"yars/internal/workflow"
)

// In the simple workflow every account is a director; anna is the admin.
var (
	anna = config.User{Username: "anna", Role: "director", IsAdmin: true}
	ben  = config.User{Username: "ben", Role: "director"}
)

// newSimpleFx is newFx for the simple workflow (config.yaml's workflow:
// simple, given to the store as serve gives it): anna (the admin) and ben,
// both on the team of acme, which holds one draft by anna, F-001 (no
// severity: Complete waits for one).
func newSimpleFx(t *testing.T) *fx {
	t.Helper()
	r, err := gitrepo.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Workflow = config.WorkflowSimple
	dbPath := filepath.Join(t.TempDir(), "yars.db")
	d, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	st := store.New(r, cfg, d)
	if err := st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, anna.GitAuthor()); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFinding("acme", "SQL injection", anna.GitAuthor()); err != nil {
		t.Fatal(err)
	}
	if err := d.AddMembers("acme", "anna", "ben"); err != nil {
		t.Fatal(err)
	}
	users := []config.User{anna, ben}
	return &fx{t: t, dir: r.Dir, dbPath: dbPath, s: &Server{Store: st, Index: index.New(st, r), Cfg: cfg, Users: func() []config.User { return users }}}
}

// initInstructions are the instructions initialize gives.
func initInstructions(f *fx) string {
	f.t.Helper()
	s, _ := f.rpc(anna, "initialize", map[string]any{})["result"].(map[string]any)["instructions"].(string)
	return s
}

// The simple workflow's instructions tell of draft → complete → reported,
// with no reviewers or roles, and which transitions to confirm; the
// standard ones stay as they were.
func TestSimpleInstructions(t *testing.T) {
	got := initInstructions(newSimpleFx(t))
	for _, w := range []string{"draft → complete → reported", "no reviewers or roles", "the statuses are draft, complete, reported, withdrawn",
		"its hash as transition's base to complete the version you read", "confirm workflow transitions (complete, report, revert, withdraw)"} {
		if !strings.Contains(got, w) {
			t.Errorf("lacks %q:\n%s", w, got)
		}
	}
	for _, w := range []string{"verification", "submit", "approve", "sign off", "sign_off", "clear", "take_back"} {
		if strings.Contains(got, w) {
			t.Errorf("says %q:\n%s", w, got)
		}
	}
	if std := initInstructions(newFx(t)); std != instructions {
		t.Errorf("the standard instructions changed:\n%s", std)
	}
}

// listedTools are tools/list's tools by name.
func listedTools(f *fx) map[string]map[string]any {
	f.t.Helper()
	out := map[string]map[string]any{}
	for _, tl := range f.rpc(anna, "tools/list", map[string]any{})["result"].(map[string]any)["tools"].([]any) {
		m := tl.(map[string]any)
		out[m["name"].(string)] = m
	}
	return out
}

// sameAsListed reports where tools/list differs from the catalogue cat: a
// tool's description or a parameter's.
func sameAsListed(t *testing.T, listed map[string]map[string]any, cat []ToolDoc) {
	t.Helper()
	if len(listed) != len(cat) {
		t.Fatalf("%d tools listed, %d in the catalogue", len(listed), len(cat))
	}
	for _, td := range cat {
		m := listed[td.Name]
		if m == nil || m["description"] != td.Desc {
			t.Errorf("%s: listed %v, catalogue %q", td.Name, m["description"], td.Desc)
			continue
		}
		props := m["inputSchema"].(map[string]any)["properties"].(map[string]any)
		for _, p := range td.Params {
			if pm, _ := props[p.Name].(map[string]any); pm == nil || pm["description"] != p.Desc {
				t.Errorf("%s %s: listed %v, catalogue %q", td.Name, p.Name, props[p.Name], p.Desc)
			}
		}
	}
}

// standardWords are the standard workflow's words for its review steps,
// reviewers and roles.
var standardWords = regexp.MustCompile(`(?i)\b(verification|submit\w*|approv\w*|sign[ _-]?offs?|review\w*|roles?|directors?|take_back|cleared|clearances?|returned|return reason)\b`)

// tools/list words the tools as the simple workflow has them: no review
// steps, reviewers or roles; transition takes the simple workflow's actions
// and list_findings its statuses. The docs' catalogue (CatalogFor) says the
// same; the standard workflow's text is as it was (Catalog).
func TestSimpleToolsList(t *testing.T) {
	simple := CatalogFor(workflow.Flow{Simple: true})
	sameAsListed(t, listedTools(newSimpleFx(t)), simple)
	for _, td := range simple {
		text := td.Desc
		for _, p := range td.Params {
			text += " " + p.Desc
		}
		if w := standardWords.FindString(text); w != "" {
			t.Errorf("%s says %q: %s", td.Name, w, text)
		}
	}
	paramDesc := func(cat []ToolDoc, tool, name string) string {
		for _, td := range cat {
			for _, p := range td.Params {
				if td.Name == tool && p.Name == name {
					return p.Desc
				}
			}
		}
		return ""
	}
	if got := paramDesc(simple, "transition", "action"); got != "complete | reopen | report | unreport | revert | withdraw | revise" {
		t.Errorf("transition's actions: %q", got)
	}
	if got := paramDesc(simple, "list_findings", "status"); !strings.HasPrefix(got, "one of draft, complete, reported, withdrawn ") {
		t.Errorf("list_findings' statuses: %q", got)
	}
	// each simple text names parameters the tool has
	for _, tl := range tools {
		if tl.simple == nil {
			continue
		}
		for name := range tl.simple.params {
			if !slices.ContainsFunc(slices.Concat(tl.required, tl.optional, tl.boolArgs), func(p param) bool { return p.name == name }) {
				t.Errorf("%s has no parameter %s", tl.name, name)
			}
		}
	}
	// the standard workflow's: the tools' own text
	std := Catalog()
	sameAsListed(t, listedTools(newFx(t)), std)
	if !reflect.DeepEqual(std, CatalogFor(workflow.Flow{})) {
		t.Error("Catalog is not the standard workflow's")
	}
	for i, tl := range tools {
		if std[i].Name != tl.name || std[i].Desc != tl.desc {
			t.Errorf("%s: %q", tl.name, std[i].Desc)
		}
	}
}

// configOf is get_config's workflow, statuses and actions.
type configOf struct {
	Workflow string   `json:"workflow"`
	Statuses []string `json:"statuses"`
	Actions  []string `json:"actions"`
}

func getConfigOf(t *testing.T, f *fx) configOf {
	t.Helper()
	var c configOf
	if err := json.Unmarshal([]byte(f.ok(anna, "get_config", nil)), &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// get_config names the workflow (in both) and gives the simple workflow's
// statuses and actions (revert, the step back by status, too).
func TestSimpleGetConfig(t *testing.T) {
	c := getConfigOf(t, newSimpleFx(t))
	if c.Workflow != "simple" || fmt.Sprint(c.Statuses) != "[draft complete reported withdrawn]" ||
		fmt.Sprint(c.Actions) != "[complete reopen report unreport withdraw revise revert]" {
		t.Fatalf("%+v", c)
	}
	std := getConfigOf(t, newFx(t))
	if std.Workflow != "standard" || !slices.Equal(std.Statuses, workflow.AllStatuses) ||
		fmt.Sprint(std.Actions) != "[submit return clear approve reopen report unreport withdraw revise take_back revert]" {
		t.Fatalf("standard %+v", std)
	}
}

// whoami gives no role in the simple workflow: whether one is an admin is
// the only difference between accounts.
func TestSimpleWhoamiNoRole(t *testing.T) {
	f := newSimpleFx(t)
	for _, u := range []config.User{anna, ben} {
		m := object(t, "whoami", f.ok(u, "whoami", nil))
		if _, has := m["role"]; has || m["username"] != u.Username || m["admin"] != u.IsAdmin {
			t.Errorf("%s: %v", u.Username, m)
		}
	}
	tok := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{"read"}}
	text, _ := f.callTok(ben, tok, "whoami", nil)
	if m := object(t, "whoami", text); m["role"] != nil || m["token"] == nil {
		t.Errorf("with a token: %v", m)
	}
}

// list_team names the members without roles in the simple workflow.
func TestSimpleListTeamNoRoles(t *testing.T) {
	f := newSimpleFx(t)
	text := f.ok(ben, "list_team", map[string]any{"engagement": "acme"})
	var team []map[string]any
	itemsOf(t, text, &team)
	if len(team) != 2 || team[0]["username"] != "anna" || team[1]["username"] != "ben" {
		t.Fatalf("%s", text)
	}
	for _, m := range team {
		if _, has := m["role"]; has {
			t.Errorf("a role: %s", text)
		}
	}
}
