package web

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"

	"yars/internal/db"
	"yars/internal/rules"
)

// webFixer is the test's rules engine with a programmed Fix and a provider.
type webFixer struct {
	*rules.Engine
	mu    sync.Mutex
	calls int
	block chan struct{} // when set, Fix waits for it
	ai    bool
}

func (f *webFixer) Fix(_ context.Context, _ rules.Violation, _, body string) (string, error) {
	f.mu.Lock()
	f.calls++
	block := f.block
	f.mu.Unlock()
	if block != nil {
		<-block
	}
	return strings.ReplaceAll(body, "foo", "bar"), nil
}

func (f *webFixer) AIConfigured() bool { return f.ai }

const fooRule = "- id: no-foo\n  target: section:Impact\n  regex_forbid: 'foo'\n  level: warning\n  message: Avoid foo\n"

// fixEnv has a finding whose Impact breaks no-foo, checked, and a fake
// fixer with a provider (ai).
func fixEnv(t *testing.T, ai bool) (*env, *webFixer) {
	t.Helper()
	e := setup(t)
	e.rules(t, fooRule, nil)
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "a foo here", "", wAlice); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks", nil, hxReq); rec.Code != 200 {
		t.Fatalf("check %d", rec.Code)
	}
	e.srv.Store.WaitChecks()
	f := &webFixer{Engine: e.srv.Rules, ai: ai}
	e.srv.Store.Linter = f
	return e, f
}

// complete marks the finding complete in the database (sign-off would ask
// for the warning to go first): only a director may edit it then.
func (e *env) complete(t *testing.T) {
	t.Helper()
	if err := e.srv.Store.DB().Tx(func(tx *db.Tx) error {
		return tx.PutState("acme", "F-001", db.State{Status: "complete"})
	}); err != nil {
		t.Fatal(err)
	}
}

var fixBtnRe = regexp.MustCompile(`<button[^>]*>(?:<svg.*?</svg>)?(Fix with AI|Fixing)`)

// fixButton is the strip's Fix with AI button's tag, "" when absent.
func fixButton(t *testing.T, b string) string {
	t.Helper()
	return fixBtnRe.FindString(checksPanel(t, b))
}

func TestFixButtonStates(t *testing.T) {
	e, f := fixEnv(t, true)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	btn := fixButton(t, b)
	if !strings.Contains(btn, `hx-post="/e/acme/f/001/checks/fix"`) || strings.Contains(btn, " disabled") || !strings.Contains(btn, "w152") || !strings.Contains(btn, "secondary") {
		t.Fatalf("author with a provider: %q", btn)
	}
	// it sits left of the state slot
	head := between(checksPanel(t, b), "<summary", "</summary>")
	if i, j := strings.Index(head, "Fix with AI"), strings.Index(head, `class="slot w152"><span class="checkstate`); i < 0 || j < 0 || i > j {
		t.Fatalf("head:\n%s", head)
	}
	// without a provider: there, disabled
	f.ai = false
	if btn := fixButton(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); !strings.Contains(btn, " disabled") {
		t.Fatalf("no provider: %q", btn)
	}
	f.ai = true
	// while it runs: Fixing, disabled, the strip open
	f.block = make(chan struct{})
	if rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq); rec.Code != 200 {
		t.Fatalf("fix %d %s", rec.Code, rec.Body.String())
	}
	b = e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	btn = fixButton(t, b)
	close(f.block)
	e.srv.Store.WaitChecks()
	if !strings.HasSuffix(btn, "Fixing") || !strings.Contains(btn, " disabled") || !strings.Contains(checksPanel(t, b), "<progress") {
		t.Fatalf("running: %q", btn)
	}
	if !regexp.MustCompile(`<details class="panel checks strip[^"]*" id="checks" data-kpanel open`).MatchString(b) {
		t.Fatalf("the strip is closed while fixing:\n%s", checksPanel(t, b))
	}
	// nothing left to fix: there, disabled
	if btn := fixButton(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); !strings.Contains(btn, " disabled") || !strings.Contains(btn, "Fix with AI") {
		t.Fatalf("after the fix: %q", btn)
	}
	// a viewer who may not edit (a complete finding, not a director): an
	// empty slot instead
	e.complete(t)
	pb := checksPanel(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if fixBtnRe.FindString(pb) != "" || !strings.Contains(between(pb, "<summary", "</summary>"), `<span class="slot w152"></span>`) {
		t.Fatalf("may not edit:\n%s", between(pb, "<summary", "</summary>"))
	}
}

// A complete finding is the directors' to edit: the author's press is 403.
func TestFixRouteNeedsEditRight(t *testing.T) {
	e, f := fixEnv(t, true)
	e.complete(t)
	if rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq); rec.Code != 403 {
		t.Fatalf("alice: %d %s", rec.Code, rec.Body.String())
	}
	if f.calls != 0 {
		t.Fatal("the AI was asked")
	}
}

func TestFixRouteStartsFix(t *testing.T) {
	e, f := fixEnv(t, true)
	rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq)
	e.srv.Store.WaitChecks()
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, `id="workflow"`) || !strings.Contains(b, `id="checks"`) {
		t.Fatalf("%d:\n%s", rec.Code, b)
	}
	f.mu.Lock()
	calls := f.calls
	f.mu.Unlock()
	if calls != 1 {
		t.Fatalf("Fix called %d times", calls)
	}
	// nothing left: 400 with the store's message
	if rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq); rec.Code != 400 || !strings.Contains(rec.Body.String(), "run Check first") {
		t.Fatalf("again: %d %s", rec.Code, rec.Body.String())
	}
}

// While a fix runs, Check waits: its button is disabled and a press is 409.
func TestCheckBusyWhileFixing(t *testing.T) {
	e, f := fixEnv(t, true)
	f.block = make(chan struct{})
	if rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq); rec.Code != 200 {
		t.Fatalf("fix %d", rec.Code)
	}
	wf := wfBar(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	check := regexp.MustCompile(`<button[^>]*id="wf-check"[^>]*>`).FindString(wf)
	rec := e.do(t, "alice", "POST", fpath+"/checks", nil, hxReq)
	again := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq)
	close(f.block)
	e.srv.Store.WaitChecks()
	if !strings.Contains(check, " disabled") {
		t.Errorf("Check while fixing: %q", check)
	}
	if rec.Code != 409 || again.Code != 409 {
		t.Errorf("check %d, second fix %d", rec.Code, again.Code)
	}
}
