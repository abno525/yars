package web

import (
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/index"
	"yars/internal/notify"
	"yars/internal/store"
	"yars/internal/workflow"
)

// Admin › Users of the simple workflow: no Role column, no role select in a
// row, no Role choice in the Add user form (username, email, admin and
// password).
func TestSimpleAdminUsersNoRole(t *testing.T) {
	e := setupSimple(t)
	b := e.do(t, "anna", "GET", "/admin/users", nil, nil).Body.String()
	tbl := between(b, `<table class="table stable usertable"`, "</table>")
	if !strings.Contains(tbl, `<thead><tr><th>User</th><th class="c-flag">Admin</th><th class="c-flag">Disabled</th>`) {
		t.Fatalf("users table head:\n%s", tbl)
	}
	for _, no := range []string{"c-role", ">Role<", `name="role"`, "Role of ", ">director<"} {
		if strings.Contains(b, no) {
			t.Errorf("users page has %q", no)
		}
	}
	form := between(b, `<form class="panel compact sidecol" method="post" action="/admin/users">`, "</form>")
	for _, want := range []string{`name="username"`, `name="email"`, `name="admin"`, `name="password"`} {
		if !strings.Contains(form, want) {
			t.Errorf("add form lacks %q", want)
		}
	}
	if strings.Contains(form, "<legend>Role</legend>") || strings.Contains(form, `type="radio"`) {
		t.Fatalf("add form has a role:\n%s", form)
	}
	// the rows keep their other cells: the admin flag and Reset pass
	if !strings.Contains(tbl, `aria-label="Admin ben"`) || !strings.Contains(tbl, "Reset pass") {
		t.Fatalf("rows:\n%s", tbl)
	}
}

// Every account added in the simple workflow is a director; a posted role
// is ignored, and the audit names the admin flag only.
func TestSimpleAddUserIsDirector(t *testing.T) {
	e := setupSimple(t)
	for _, f := range []url.Values{
		{"username": {"cleo"}, "email": {"cleo@x.test"}, "role": {"pentester"}, "admin": {"1"}},
		{"username": {"dan"}, "role": {"bogus"}},
		{"username": {"eve"}},
	} {
		rec := e.do(t, "anna", "POST", "/admin/users", f, nil)
		if rec.Code != 200 || tempPwRe.FindStringSubmatch(rec.Body.String()) == nil {
			t.Fatalf("add %v: %d", f, rec.Code)
		}
	}
	for name, admin := range map[string]bool{"cleo": true, "dan": false, "eve": false} {
		u, ok := e.srv.Auth.Lookup(name)
		if !ok || u.Role != "director" || u.IsAdmin != admin {
			t.Errorf("%s: %+v", name, u)
		}
	}
	l, _ := e.srv.Store.DB().AuditLog(10)
	got := map[string]string{}
	for _, a := range l {
		if a.Action == "user.add" {
			got[a.Target] = a.Detail
		}
	}
	if len(got) != 3 || got["cleo"] != "admin" || got["dan"] != "" || got["eve"] != "" {
		t.Fatalf("audit %v", got)
	}
	// the other checks stay
	if rec := e.do(t, "anna", "POST", "/admin/users", url.Values{"username": {"bad name"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad name %d", rec.Code)
	}
	if rec := e.do(t, "anna", "POST", "/admin/users", url.Values{"username": {"cleo"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate %d", rec.Code)
	}
}

// The role endpoint answers 400 in the simple workflow and changes nothing.
func TestSimpleRoleEndpointRefused(t *testing.T) {
	e := setupSimple(t)
	rec := e.do(t, "anna", "POST", "/admin/users/ben/role", url.Values{"role": {"pentester"}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "The simple workflow has no roles") {
		t.Fatalf("role %d", rec.Code)
	}
	if u, _ := e.srv.Auth.Lookup("ben"); u.Role != "director" {
		t.Fatalf("ben %+v", u)
	}
	l, _ := e.srv.Store.DB().AuditLog(10)
	for _, a := range l {
		if a.Action == "user.role" {
			t.Fatalf("audited %+v", a)
		}
	}
	// admins only, as before
	if rec := e.do(t, "ben", "POST", "/admin/users/anna/role", url.Values{"role": {"pentester"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("ben: %d", rec.Code)
	}
}

// Settings › Account: an Access field instead of Roles: the admin tag, or a
// muted dash.
func TestSimpleSettingsAccess(t *testing.T) {
	e := setupSimple(t)
	for user, want := range map[string]string{
		"anna": `<span class="flabel">Access</span><span class="fvalue tags"><span class="tag adminflag">admin</span></span>`,
		"ben":  `<span class="flabel">Access</span><span class="fvalue tags"><span class="muted">—</span></span>`,
	} {
		b := e.do(t, user, "GET", "/settings", nil, nil).Body.String()
		acct := between(b, `id="account"`, "</form>")
		if !strings.Contains(acct, want) {
			t.Errorf("%s account:\n%s", user, acct)
		}
		if strings.Contains(acct, ">Roles<") || strings.Contains(acct, "tag role") || strings.Contains(acct, "director") {
			t.Errorf("%s: a role shown:\n%s", user, acct)
		}
	}
	// the standard workflow keeps Roles
	std := setup(t)
	if b := std.do(t, "dora", "GET", "/settings", nil, nil).Body.String(); !strings.Contains(b, `<span class="flabel">Roles</span><span class="fvalue tags"><span class="tag role">director</span><span class="tag adminflag">admin</span></span>`) {
		t.Fatal("standard Roles field")
	}
}

// A token of the simple workflow has no Assign reviewers scope: the form
// does not list it and a posted one is not taken.
func TestSimpleTokenScopes(t *testing.T) {
	e := setupSimple(t)
	b := e.do(t, "ben", "GET", "/settings/tokens/new", nil, nil).Body.String()
	if strings.Contains(b, `value="reviewers"`) || strings.Contains(b, "Assign reviewers") {
		t.Fatal("the reviewers scope is listed")
	}
	for _, a := range db.TokenActions {
		if a != "reviewers" && !strings.Contains(b, `name="action" value="`+a+`"`) {
			t.Errorf("%s not listed", a)
		}
	}
	f := url.Values{"name": {"bot"}, "kind": {"mcp"}, "access": {"actions"}, "engs": {"all"}, "expires": {"30"}, "action": {"reviewers"}}
	if rec := e.do(t, "ben", "POST", "/settings/tokens/new", f, nil); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Pick at least one action") {
		t.Fatalf("reviewers only: %d", rec.Code)
	}
	f["action"] = []string{"reviewers", "status"}
	if rec := e.do(t, "ben", "POST", "/settings/tokens/new", f, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("create %d", rec.Code)
	}
	l := e.srv.Tokens.ListFor("ben")
	if len(l) != 1 || !slices.Equal(l[0].Scopes, []string{"status"}) {
		t.Fatalf("tokens %+v", l)
	}
	// the standard workflow keeps it
	std := setup(t)
	if b := std.do(t, "alice", "GET", "/settings/tokens/new", nil, nil).Body.String(); !strings.Contains(b, `name="action" value="reviewers"`) {
		t.Fatal("standard scopes")
	}
}

// The notification settings list the simple workflow's events (Completed,
// not Approved; no review events), and saving them leaves the hidden events
// as they are.
func TestSimpleNotificationSettings(t *testing.T) {
	e := setupSimple(t)
	b := e.do(t, "ben", "GET", "/settings", nil, nil).Body.String()
	tbl := between(b, `<table class="table stable notifytable">`, "</table>")
	last := -1
	for _, ev := range notify.EventsFor(true) {
		i := strings.Index(tbl, `<td class="strong">`+ev.Label+`</td>`)
		if i < 0 || i < last {
			t.Fatalf("%s missing or out of order:\n%s", ev.Label, tbl)
		}
		last = i
	}
	if !strings.Contains(tbl, `value="approved.app"`) || !strings.Contains(tbl, `aria-label="Completed · In app"`) {
		t.Fatalf("completed row:\n%s", tbl)
	}
	for _, no := range []string{"returned.", "review.", "taken_back.", ">Approved<", "Returned to me", "Review requested", "Taken back"} {
		if strings.Contains(tbl, no) {
			t.Errorf("notification settings have %q", no)
		}
	}
	if n := strings.Count(tbl, "<tr>"); n != len(notify.EventsFor(true))+1 {
		t.Fatalf("%d rows", n)
	}
	d := e.srv.Store.DB()
	if err := d.SetNotify("ben", notify.Returned, "app", true); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "ben", "POST", "/settings/notifications", url.Values{"n": {"approved.app", "review.app", "mentioned.app"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d", rec.Code)
	}
	p, _ := d.NotifyPrefs("ben")
	if len(p) != 3 || !slices.Equal(p[notify.Returned], []string{"app"}) || !slices.Equal(p[notify.Approved], []string{"app"}) ||
		!slices.Equal(p[notify.Mentioned], []string{"app"}) {
		t.Fatalf("prefs %v", p)
	}
}

// A notice of a completed finding reads "Completed" on the notifications
// page and in the inbox; the standard workflow keeps "Approved".
func TestSimpleNotificationLabel(t *testing.T) {
	e := setupSimple(t)
	ben := config.User{Username: "ben", Role: "director"}
	fd := "F-001-sql-injection"
	if err := e.srv.Store.UpdateSeverity("acme", fd, "high", "", ben); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.Transition("acme", fd, workflow.Complete, "", ben); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/notifications", "/inbox"} {
		b := e.do(t, "anna", "GET", p, nil, nil).Body.String()
		if !strings.Contains(b, `<span class="tag nev-approved">Completed</span>`) || strings.Contains(b, `nev-approved">Approved<`) {
			t.Errorf("%s:\n%s", p, b)
		}
	}
	std := setup(t)
	if _, err := std.srv.Store.DB().AddNotification(db.Notification{User: "alice", Event: notify.Approved, Eng: "acme", Dir: fd, Fid: "F-001", Title: "SQL injection", Actor: "dora"}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/notifications", "/inbox"} {
		if b := std.do(t, "alice", "GET", p, nil, nil).Body.String(); !strings.Contains(b, `<span class="tag nev-approved">Approved</span>`) {
			t.Errorf("standard %s", p)
		}
	}
}

// The team panel has no Role column, its empty row spans the two columns
// left, and the add select names people without a role.
func TestSimpleTeamPanelNoRoles(t *testing.T) {
	e := setupSimple(t)
	e.addUser(t, config.User{Username: "cleo", Role: "director"})
	b := e.do(t, "anna", "GET", "/e/acme/settings", nil, nil).Body.String()
	tbl := between(b, `<table class="table stable teamtable flush">`, "</table>")
	if !strings.Contains(tbl, `<thead><tr><th>User</th><th class="c-act">Action</th></tr></thead>`) {
		t.Fatalf("team head:\n%s", tbl)
	}
	if strings.Contains(tbl, "director") || strings.Contains(tbl, `<td class="muted">`) {
		t.Fatalf("a role in the team:\n%s", tbl)
	}
	if !strings.Contains(tbl, `<td class="strong clip">ben</td>`) {
		t.Fatalf("ben not listed:\n%s", tbl)
	}
	add := between(b, `<select class="grow flush" name="user"`, "</select>")
	if !strings.Contains(add, `<option value="cleo">cleo</option>`) || strings.Contains(add, " · ") {
		t.Fatalf("add select:\n%s", add)
	}
	if err := e.srv.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, gitrepo.Author{Name: "anna", Email: "anna@yars.local"}); err != nil {
		t.Fatal(err)
	}
	b = e.do(t, "anna", "GET", "/e/beta/settings", nil, nil).Body.String()
	if tbl := between(b, `<table class="table stable teamtable flush">`, "</table>"); !strings.Contains(tbl, `<tr class="emptyrow"><td colspan="2">—</td></tr>`) {
		t.Fatalf("empty team:\n%s", tbl)
	}
	if n := checkEmptyRows(t, "simple /e/beta/settings", b); n != 1 {
		t.Fatalf("%d empty tables", n)
	}
	// the standard workflow keeps the roles, and its empty row spans three
	std := setup(t)
	b = std.do(t, "dora", "GET", "/e/acme/settings", nil, nil).Body.String()
	if !strings.Contains(b, `<th class="c-role">Role</th>`) || !strings.Contains(b, `<td class="muted">pentester</td>`) {
		t.Fatal("standard team panel")
	}
	if err := std.srv.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, gitrepo.Author{Name: "dora", Email: "dora@yars.local"}); err != nil {
		t.Fatal(err)
	}
	b = std.do(t, "dora", "GET", "/e/beta/settings", nil, nil).Body.String()
	if !strings.Contains(b, `<tr class="emptyrow"><td colspan="3">—</td></tr>`) || checkEmptyRows(t, "standard /e/beta/settings", b) != 1 {
		t.Fatal("standard empty team")
	}
}

// The new-engagement form and the retest form name people without roles.
func TestSimpleNewEngagementAndRetestNoRoles(t *testing.T) {
	e := setupSimple(t)
	b := e.do(t, "anna", "GET", "/engagements/new", nil, nil).Body.String()
	team := between(b, `<div class="neteamlist">`, "</fieldset>")
	if !strings.Contains(team, `<span class="strong clip">anna</span><span class="muted"></span>`) ||
		!strings.Contains(team, `<span class="strong clip">ben</span><span class="muted"></span>`) || strings.Contains(team, "director") {
		t.Fatalf("new engagement team:\n%s", team)
	}
	b = e.do(t, "anna", "GET", "/e/acme/retest/new", nil, nil).Body.String()
	sel := between(b, `<select name="assignee">`, "</select>")
	if !strings.Contains(sel, `<option value="ben">ben</option>`) || strings.Contains(sel, "director") || strings.Contains(sel, "(") {
		t.Fatalf("retester select:\n%s", sel)
	}
	// the standard workflow keeps them
	std := setup(t)
	if b := std.do(t, "dora", "GET", "/engagements/new", nil, nil).Body.String(); !strings.Contains(b, `<span class="strong clip">alice</span><span class="muted">pentester</span>`) {
		t.Fatal("standard new engagement")
	}
	if b := std.do(t, "dora", "GET", "/e/acme/retest/new", nil, nil).Body.String(); !strings.Contains(b, ">alice (pentester)</option>") {
		t.Fatal("standard retest")
	}
}

// freshSimple is a server of the simple workflow on a new data directory
// without any account.
func freshSimple(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	r, err := gitrepo.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	cfg := config.Default()
	cfg.Workflow = config.WorkflowSimple
	st := store.New(r, cfg, d)
	s := &Server{Store: st, Index: index.New(st, r), Auth: auth.New(d), Cfg: cfg}
	t.Cleanup(s.Close)
	return &env{srv: s, h: s.Handler(), dir: dir, toks: map[string]string{}}
}

// /setup of the simple workflow tags the first account admin only; the
// account is stored as a director, as in the standard one.
func TestSimpleSetupTags(t *testing.T) {
	e := freshSimple(t)
	b := e.do(t, "", "GET", "/setup", nil, nil).Body.String()
	head := between(b, `<div class="barehead">`, "</div>")
	if head != `<div class="barehead"><h1>Set up YARS</h1><span class="tag adminflag">admin</span>` {
		t.Fatalf("setup head: %q", head)
	}
	rec := e.do(t, "", "POST", "/setup", url.Values{"username": {"anna"}, "password": {"long enough pw"}, "repeat": {"long enough pw"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("setup %d", rec.Code)
	}
	if u, ok := e.srv.Auth.Lookup("anna"); !ok || u.Role != "director" || !u.IsAdmin {
		t.Fatalf("anna %+v", u)
	}
	std := fresh(t)
	if b := std.do(t, "", "GET", "/setup", nil, nil).Body.String(); !strings.Contains(b, `<span class="tag role">director</span><span class="tag adminflag">admin</span>`) {
		t.Fatal("standard setup tags")
	}
}

// Admin › Rules: Require Check comes before Complete in the simple workflow.
func TestSimpleRequireCheckLabel(t *testing.T) {
	e := setupSimple(t)
	e.rules(t, noneRule, nil)
	b := e.do(t, "anna", "GET", "/admin/rules", nil, nil).Body.String()
	tbl := between(b, `<table class="table ruletable settingtable">`, "</table>")
	if !strings.Contains(tbl, `<td class="setname">Require Check before Complete</td>`) || !strings.Contains(tbl, `aria-label="Require Check before Complete"`) {
		t.Fatalf("settings table:\n%s", tbl)
	}
	if strings.Contains(tbl, "Sign off") || strings.Contains(tbl, "Approve") {
		t.Fatalf("standard wording left:\n%s", tbl)
	}
}

// Admin › System names the simple workflow; the standard one adds no row.
func TestSimpleSystemWorkflow(t *testing.T) {
	e := setupSimple(t)
	b := e.do(t, "anna", "GET", "/admin/system", nil, nil).Body.String()
	if !strings.Contains(b, `<div class="stats">
      <div class="st wide"><span class="sl">Workflow</span><span class="sv" title="Simple (set by yars init)">Simple (set by yars init)</span></div>
    </div>`) {
		t.Fatalf("no workflow row:\n%s", between(b, "<h2>Server</h2>", "</section>"))
	}
	std := setup(t)
	if b := std.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String(); strings.Contains(b, ">Workflow<") {
		t.Fatal("a workflow row in the standard workflow")
	}
}
