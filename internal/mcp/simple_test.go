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

// f001 is the arguments naming the fixture's finding, plus the given ones
// (name, value, name, value…).
func f001(kv ...string) map[string]any {
	m := map[string]any{"engagement": "acme", "finding": "F-001"}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// simpleRead is read_finding's status and hash.
func simpleRead(t *testing.T, f *fx) (status, hash string) {
	t.Helper()
	m := object(t, "read_finding", f.ok(anna, "read_finding", f001()))
	st, _ := m["state"].(map[string]any)["status"].(string)
	h, _ := m["hash"].(string)
	return st, h
}

// Complete takes a draft to complete for the version read (base), and
// says so; report, then revert twice, takes it back to complete and to
// draft, each answer naming the status it is now.
func TestSimpleTransitionComplete(t *testing.T) {
	f := newSimpleFx(t)
	f.ok(anna, "set_field", f001("field", "severity", "value", "high"))
	_, old := simpleRead(t, f)
	f.ok(anna, "update_section", f001("section", "Impact", "body", "Full read."))
	// a base the finding no longer has: read it again
	text, isErr := f.call(ben, "transition", f001("action", "complete", "base", old))
	if !isErr || object(t, "complete", text)["code"] != "conflict" {
		t.Fatalf("a stale base: %s", text)
	}
	if st, _ := simpleRead(t, f); st != "draft" {
		t.Fatalf("status %s", st)
	}
	_, hash := simpleRead(t, f)
	steps := []struct {
		user                         config.User
		action, reason, says, status string
	}{
		{ben, "complete", "", "complete done; status is now complete", "complete"},
		{anna, "report", "", "report done; status is now reported", "reported"},
		{anna, "revert", "a typo", "unreport done; status is now complete", "complete"},
		{ben, "revert", "more work", "reopen done; status is now draft", "draft"},
	}
	for _, s := range steps {
		text := f.ok(s.user, "transition", f001("action", s.action, "reason", s.reason, "base", hash))
		if message(t, text) != s.says {
			t.Errorf("%s: %s", s.action, text)
		}
		if st, _ := simpleRead(t, f); st != s.status {
			t.Errorf("%s: status %s", s.action, st)
		}
	}
	text, isErr = f.call(anna, "transition", f001("action", "revert", "reason", "again"))
	if !isErr || message(t, text) != "nothing to revert: the finding is draft" {
		t.Errorf("revert a draft: %s", text)
	}
}

// In the simple workflow any account marks a complete finding reported, the
// author's or not.
func TestSimpleReportByAnyone(t *testing.T) {
	f := newSimpleFx(t)
	f.ok(anna, "set_field", f001("field", "severity", "value", "high"))
	f.ok(anna, "transition", f001("action", "complete"))
	if text := f.ok(ben, "transition", f001("action", "report")); message(t, text) != "report done; status is now reported" {
		t.Fatalf("report by ben: %s", text)
	}
	if st, _ := simpleRead(t, f); st != "reported" {
		t.Fatalf("status %s", st)
	}
}

// The standard workflow's steps are refused by name, as not part of the
// simple workflow (with a reason, without one, with a stale base: never a
// request for a reason or a conflict); an unknown action lists the simple
// workflow's actions.
func TestSimpleTransitionSubmitRefused(t *testing.T) {
	f := newSimpleFx(t)
	f.ok(anna, "set_field", f001("field", "severity", "value", "high"))
	for _, act := range []string{"submit", "return", "clear", "sign_off", "approve", "take_back"} {
		for _, a := range []map[string]any{f001("action", act, "reason", "because"), f001("action", act), f001("action", act, "base", "a hash the finding never had")} {
			text, isErr := f.call(anna, "transition", a)
			if m := object(t, act, text); !isErr || m["code"] != "not_allowed" || !strings.HasSuffix(message(t, text), " is not part of the simple workflow (draft → complete → reported)") {
				t.Errorf("%v: %s", a, text)
			}
		}
	}
	text, isErr := f.call(anna, "transition", f001("action", "lock"))
	if m := object(t, "lock", text); !isErr || m["code"] != "invalid" || m["message"] != "unknown action (complete, reopen, report, unreport, revert, withdraw, revise)" {
		t.Errorf("unknown: %s", text)
	}
	if st, _ := simpleRead(t, f); st != "draft" {
		t.Errorf("status %s", st)
	}
}

// list_findings takes the simple workflow's statuses: verification is
// unknown there.
func TestSimpleListFindingsStatus(t *testing.T) {
	f := newSimpleFx(t)
	text, isErr := f.call(anna, "list_findings", map[string]any{"engagement": "acme", "status": "verification"})
	if m := object(t, "list_findings", text); !isErr || m["code"] != "invalid" ||
		m["message"] != `unknown status "verification"; valid statuses: draft, complete, reported, withdrawn` {
		t.Fatalf("%s", text)
	}
	f.ok(anna, "set_field", f001("field", "severity", "value", "high"))
	f.ok(anna, "transition", f001("action", "complete"))
	for st, n := range map[string]int{"complete": 1, "draft": 0, "": 1} {
		var rows []struct{ ID, Status string }
		itemsOf(t, f.ok(anna, "list_findings", map[string]any{"engagement": "acme", "status": st}), &rows)
		if len(rows) != n || (n == 1 && rows[0].Status != "complete") {
			t.Errorf("status %q: %+v", st, rows)
		}
	}
}

// set_field reviewers is refused by the store, whatever the names: the
// simple workflow has no reviewers (not_allowed, not a name's fault).
func TestSimpleSetReviewersRefused(t *testing.T) {
	f := newSimpleFx(t)
	for _, names := range []string{"ben", "anna", "nobody", ""} {
		text, isErr := f.call(anna, "set_field", f001("field", "reviewers", "value", names))
		if m := object(t, names, text); !isErr || m["code"] != "not_allowed" || m["message"] != "not allowed: the simple workflow has no reviewers" {
			t.Errorf("%q: %s", names, text)
		}
	}
	var rd struct {
		State struct {
			Reviewers []string `json:"reviewers"`
		} `json:"state"`
	}
	json.Unmarshal([]byte(f.ok(anna, "read_finding", f001())), &rd)
	if len(rd.State.Reviewers) != 0 {
		t.Errorf("reviewers %v", rd.State.Reviewers)
	}
}

// Over HTTP too, set_field reviewers is refused because the simple workflow
// has no reviewers, not because the token lacks an action the simple server
// never offers: a token with every other action, or the CLI's, reaches the
// store's refusal; set_field is an edit, so a token that may not edit is
// refused that.
func TestSimpleSetReviewersTokenRefused(t *testing.T) {
	f := newSimpleFx(t)
	var offered []string
	for _, a := range db.TokenActions {
		if a != "reviewers" {
			offered = append(offered, a)
		}
	}
	cases := []struct {
		tok  db.TokenInfo
		says string
	}{
		{db.TokenInfo{Kind: db.TokenMCP, Scopes: offered}, "not allowed: the simple workflow has no reviewers"},
		{db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{"edit"}}, "not allowed: the simple workflow has no reviewers"},
		{db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeAll}}, "not allowed: the simple workflow has no reviewers"},
		{db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}}, "not allowed: this token may not edit findings"},
		{db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{"reviewers"}}, "not allowed: this token may not edit findings"},
	}
	for _, c := range cases {
		for _, u := range []config.User{anna, ben} {
			text, isErr := f.callTok(u, c.tok, "set_field", f001("field", "reviewers", "value", "ben"))
			if m := object(t, "set_field", text); !isErr || m["code"] != "not_allowed" || m["message"] != c.says {
				t.Errorf("%s with %v: %s", u.Username, c.tok.Scopes, text)
			}
		}
	}
	var rd struct {
		State struct {
			Reviewers []string `json:"reviewers"`
		} `json:"state"`
	}
	json.Unmarshal([]byte(f.ok(anna, "read_finding", f001())), &rd)
	if len(rd.State.Reviewers) != 0 {
		t.Errorf("reviewers %v", rd.State.Reviewers)
	}
}

// fix_checks on a finding past draft says Fix with AI works on drafts, as
// the simple workflow's tools/list says; the standard workflow's refusal
// still names verification.
func TestSimpleFixChecksDraftsOnly(t *testing.T) {
	for _, state := range []string{"complete", "reported", "withdrawn"} {
		f := simpleStateFx(t, state)
		text, isErr := f.call(ben, "fix_checks", f001())
		if m := object(t, state, text); !isErr || m["code"] != "not_allowed" || m["message"] != "not allowed: this finding is "+state+"; Fix with AI works on drafts" {
			t.Errorf("%s: %s", state, text)
		}
	}
	f := newFx(t)
	f.ok(alice, "transition", map[string]any{"engagement": "acme", "finding": "F-001", "action": "withdraw", "reason": "out of scope"})
	text, isErr := f.call(dora, "fix_checks", map[string]any{"engagement": "acme", "finding": "F-001"})
	if m := object(t, "standard", text); !isErr || m["message"] != "not allowed: this finding is withdrawn; Fix with AI works on drafts and findings in verification" {
		t.Errorf("standard: %s", text)
	}
}

// list_notifications names a completion "completed" in the simple
// workflow, which has no approval; the other events keep their names, and
// the standard workflow's approval stays "approved".
func TestSimpleNotificationsCompleted(t *testing.T) {
	events := func(f *fx, u config.User) string {
		var notes []struct{ Event, By string }
		itemsOf(t, f.ok(u, "list_notifications", nil), &notes)
		var out []string
		for _, n := range notes {
			out = append(out, n.Event+" by "+n.By)
		}
		return strings.Join(out, ", ")
	}
	f := newSimpleFx(t)
	d := f.s.Store.DB()
	d.AddUser(anna)
	d.AddNotification(db.Notification{User: "anna", Event: "reply", Eng: "acme", Fid: "F-001", Actor: "ben", Text: "done"})
	d.AddNotification(db.Notification{User: "anna", Event: "approved", Eng: "acme", Fid: "F-001", Actor: "ben"})
	d.AddNotification(db.Notification{User: "anna", Event: "reverted", Eng: "acme", Fid: "F-001", Actor: "ben", Text: "a typo"})
	if got := events(f, anna); got != "reverted by ben, completed by ben, reply by ben" {
		t.Errorf("simple: %s", got)
	}
	std := newFx(t)
	std.s.Store.DB().AddUser(alice)
	std.s.Store.DB().AddNotification(db.Notification{User: "alice", Event: "approved", Eng: "acme", Fid: "F-001", Actor: "dora"})
	if got := events(std, alice); got != "approved by dora" {
		t.Errorf("standard: %s", got)
	}
}

// simpleStateFx is a simple-workflow fixture whose F-001 is in state:
// draft (no severity: not ready), ready (severity high), complete,
// reported, withdrawn.
func simpleStateFx(t *testing.T, state string) *fx {
	t.Helper()
	f := newSimpleFx(t)
	if state == "draft" {
		return f
	}
	f.ok(anna, "set_field", f001("field", "severity", "value", "high"))
	steps := map[string][]string{"complete": {"complete"}, "reported": {"complete", "report"}, "withdrawn": {"withdraw"}}
	for _, act := range steps[state] {
		f.ok(anna, "transition", f001("action", act, "reason", "because"))
	}
	return f
}

// simpleCloneOf is a server on f's folder without the database (yars mcp
// on a clone), with f's simple config.yaml.
func simpleCloneOf(t *testing.T, f *fx) *fx {
	t.Helper()
	r, err := gitrepo.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(r, f.s.Cfg, nil)
	return &fx{t: t, dir: f.dir, s: &Server{Store: st, Index: index.New(st, r), Cfg: f.s.Cfg}}
}

// Each action read_finding lists in the simple workflow goes through
// transition when it is enabled, and is refused with its reason when not:
// as it is, with style rules, archived, through a token, on a clone. The
// actions listed are the simple workflow's of the status.
func TestSimpleAllowedActions(t *testing.T) {
	want := map[string]string{"draft": "complete withdraw", "ready": "complete withdraw", "complete": "reopen report withdraw",
		"reported": "unreport withdraw", "withdrawn": "revise"}
	for _, mode := range matchModes {
		if mode.name == "clone" {
			mode.prep = simpleCloneOf
		}
		states := []string{"draft", "ready", "complete", "reported", "withdrawn"}
		if mode.name != "plain" {
			states = []string{"ready", "complete"}
		}
		for _, state := range states {
			for _, u := range []config.User{anna, ben} {
				call := func(f *fx, tool string, a map[string]any) (string, bool) {
					if mode.tok != nil {
						return f.callTok(u, *mode.tok, tool, a)
					}
					return f.call(u, tool, a)
				}
				where := mode.name + " " + state + "/" + u.Username
				var rd struct {
					Allowed []workflow.Allowed `json:"allowed_actions"`
				}
				text, isErr := call(mode.prep(t, simpleStateFx(t, state)), "read_finding", f001())
				if isErr {
					t.Fatalf("%s: %s", where, text)
				}
				json.Unmarshal([]byte(text), &rd)
				var names []string
				for _, al := range rd.Allowed {
					names = append(names, al.Action)
				}
				listed := want[state]
				if mode.name == "clone" {
					listed = want["draft"] // a clone holds no workflow state: every finding reads as a draft
				}
				if got := strings.Join(names, " "); got != listed {
					t.Errorf("%s: actions %s", where, got)
				}
				if mode.name == "plain" && state == "draft" && (rd.Allowed[0].Enabled || !strings.Contains(rd.Allowed[0].Reason, "cannot complete: set a CVSS vector or a severity")) {
					t.Errorf("%s: complete %+v", where, rd.Allowed[0])
				}
				for _, al := range rd.Allowed {
					text, isErr := call(mode.prep(t, simpleStateFx(t, state)), "transition", f001("action", al.Action, "reason", "because"))
					switch {
					case al.Enabled && isErr:
						t.Errorf("%s %s listed enabled, refused: %s", where, al.Action, text)
					case !al.Enabled && !isErr:
						t.Errorf("%s %s listed disabled (%s), done", where, al.Action, al.Reason)
					case !al.Enabled && (al.Reason == "" || !strings.Contains(message(t, text), al.Reason)):
						t.Errorf("%s %s: listed %q, refused %q", where, al.Action, al.Reason, message(t, text))
					}
					if al.Needs != "reason" {
						continue
					}
					// without the reason it needs: a disabled action is refused
					// for the listed reason first, an enabled one asks for it
					text, _ = call(mode.prep(t, simpleStateFx(t, state)), "transition", f001("action", al.Action))
					m := object(t, al.Action, text)
					switch {
					case al.Enabled && m["code"] != "invalid":
						t.Errorf("%s %s without a reason: %s", where, al.Action, text)
					case !al.Enabled && !strings.Contains(m["message"].(string), al.Reason):
						t.Errorf("%s %s without a reason: listed %q, refused %s", where, al.Action, al.Reason, text)
					}
				}
			}
		}
	}
}
