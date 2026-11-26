package web

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/notify"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

// setupSimple is setup for the simple workflow (config.yaml's workflow:
// simple, given to the store as serve gives it): anna (director and admin)
// and ben (director; every account of the simple workflow is a director),
// both on the team of engagement acme ("ACME Web"), which holds one draft
// by anna, F-001-sql-injection ("SQL injection", no severity: as setup's,
// Complete waits for one). The test runs in parallel, as with setup.
func setupSimple(t *testing.T) *env {
	t.Helper()
	parallelOnce(t)
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
	// the cleanups let go of what they closed, as newEnv's do
	t.Cleanup(func() { d.Close(); d = nil })
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
	t.Cleanup(func() { s.Close(); s = nil })
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

// mailbox keeps the email a notifier sends.
type mailbox struct {
	mu   sync.Mutex
	sent []string // subject, then body
}

func (m *mailbox) Send(_, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, subject, body)
	return nil
}

// The server's notifier names the events as its workflow does: ben
// completing anna's finding emails her "Completed", not "Approved".
func TestSimpleCompletedEmail(t *testing.T) {
	e := setupSimple(t)
	d := e.srv.Store.DB()
	if err := d.SetEmail("anna", "anna@acme.example"); err != nil {
		t.Fatal(err)
	}
	if err := d.SetNotify("anna", notify.Approved, "email", true); err != nil {
		t.Fatal(err)
	}
	m := &mailbox{}
	e.srv.Notifier.Mail = m
	ben := config.User{Username: "ben", Role: "director"}
	fd := "F-001-sql-injection"
	if err := e.srv.Store.UpdateSeverity("acme", fd, "high", "", ben); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.Transition("acme", fd, workflow.Complete, "", ben); err != nil {
		t.Fatal(err)
	}
	e.srv.Notifier.Wait()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) != 2 || m.sent[0] != "[YARS] Completed: F-001 SQL injection" || !strings.HasPrefix(m.sent[1], "Completed · ben\n") {
		t.Fatalf("sent %q", m.sent)
	}
}
