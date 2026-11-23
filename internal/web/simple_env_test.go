package web

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/index"
	"yars/internal/store"
	"yars/internal/workflow"
)

// setupSimple is setup for the simple workflow (config.yaml's workflow:
// simple, given to the store as serve gives it): anna (director and admin)
// and ben (director; every account of the simple workflow is a director),
// both on the team of engagement acme ("ACME Web"), which holds one draft
// by anna, F-001-sql-injection ("SQL injection", no severity: as setup's,
// Complete waits for one). The test runs in parallel, as with setup.
func setupSimple(t *testing.T) *env {
	t.Helper()
	if _, again := paralleled.LoadOrStore(t, true); !again {
		t.Parallel()
	}
	hashOnce.Do(func() {
		h, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
		pwHash = string(h)
	})
	dir := t.TempDir()
	r, err := gitrepo.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Workflow = config.WorkflowSimple
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	st := store.New(r, cfg, d)
	a := gitrepo.Author{Name: "anna", Email: "anna@yars.local"}
	if err := st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME Web"}, a); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFinding("acme", "SQL injection", a); err != nil {
		t.Fatal(err)
	}
	users := []config.User{
		{Username: "anna", Role: "director", PasswordHash: pwHash, IsAdmin: true},
		{Username: "ben", Role: "director", PasswordHash: pwHash},
	}
	for _, u := range users {
		if err := d.AddUser(u); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.AddMembers("acme", "anna", "ben"); err != nil {
		t.Fatal(err)
	}
	au := auth.New(d)
	s := &Server{Store: st, Index: index.New(st, r), Auth: au, Cfg: cfg}
	e := &env{srv: s, h: s.Handler(), dir: dir, toks: map[string]string{}, parallel: true}
	t.Cleanup(s.Close)
	for _, u := range users {
		tok, ok := au.Login(u.Username, "pw")
		if !ok {
			t.Fatal("login failed")
		}
		e.toks[u.Username] = tok
	}
	return e
}

// probeSimple renders {{if simple}} with one of the server's page sets.
func probeSimple(t *testing.T, e *env) string {
	t.Helper()
	tpl, err := e.srv.pages["engagement.html"].Clone()
	if err != nil {
		t.Fatal(err)
	}
	if tpl, err = tpl.New("probe").Parse(`{{if simple}}simple{{else}}standard{{end}}`); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	if err := tpl.ExecuteTemplate(&b, "probe", nil); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// Complete has Approve's key: Shift+A completes a finding in either
// workflow.
func TestSimpleCompleteKey(t *testing.T) {
	if wfKeys[workflow.Complete] != "Shift+A" || wfKeys[workflow.Approve] != "Shift+A" {
		t.Fatalf("keys %q %q", wfKeys[workflow.Complete], wfKeys[workflow.Approve])
	}
}

// Every template can ask {{if simple}}: true on a server of the simple
// workflow, false otherwise (the default of the shared funcs).
func TestSimpleTemplateFunc(t *testing.T) {
	e := setupSimple(t)
	if got := probeSimple(t, e); got != "simple" {
		t.Fatalf("simple server: %q", got)
	}
	if !e.srv.flow().Simple {
		t.Fatal("flow")
	}
	std := setup(t)
	if got := probeSimple(t, std); got != "standard" {
		t.Fatalf("standard server: %q", got)
	}
	if std.srv.flow().Simple {
		t.Fatal("standard flow")
	}
	if f, ok := funcs["simple"].(func() bool); !ok || f() {
		t.Fatal("the shared default")
	}
	// the env: both open the engagement; anna is the admin
	for _, u := range []string{"anna", "ben"} {
		if rec := e.do(t, u, "GET", "/e/acme/f/F-001-sql-injection", nil, nil); rec.Code != 200 {
			t.Fatalf("%s: code %d", u, rec.Code)
		}
	}
	if rec := e.do(t, "anna", "GET", "/admin", nil, nil); rec.Code != 303 {
		t.Fatalf("anna /admin: %d", rec.Code)
	}
	if rec := e.do(t, "ben", "GET", "/admin", nil, nil); rec.Code != 403 {
		t.Fatalf("ben /admin: %d", rec.Code)
	}
}
