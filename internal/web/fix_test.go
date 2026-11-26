package web

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/rules"
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
	return e, fixSetup(t, e, fooRule, nil, ai)
}

// fixSetup loads the rules (and scripts), breaks no-foo in Impact, checks,
// and puts the fake fixer in place.
func fixSetup(t *testing.T, e *env, rulesYAML string, scripts map[string]string, ai bool) *webFixer {
	t.Helper()
	e.rules(t, rulesYAML, scripts)
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "a foo here", "", wAlice); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks", nil, hxReq); rec.Code != 200 {
		t.Fatalf("check %d", rec.Code)
	}
	e.srv.Store.WaitChecks()
	f := &webFixer{Engine: e.srv.Rules, ai: ai}
	e.srv.Store.Linter = f
	return f
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
	// data-kskip: Enter on the selected strip does not start a fix
	if !strings.Contains(btn, `hx-post="/e/acme/f/001/checks/fix"`) || strings.Contains(btn, " disabled") || !strings.Contains(btn, "w152") || !strings.Contains(btn, "secondary") || !strings.Contains(btn, " data-kskip") {
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
	// bob is not the author: his strip is open only because a fix runs
	bobStrip := e.do(t, "bob", "GET", fpath+"/checks", nil, nil).Body.String()
	close(f.block)
	e.srv.Store.WaitChecks()
	if !strings.HasSuffix(btn, "Fixing") || !strings.Contains(btn, " disabled") || !strings.Contains(checksPanel(t, b), "<progress") {
		t.Fatalf("running: %q", btn)
	}
	// open, and marked running: the user's stored choice does not close it
	if !regexp.MustCompile(`<details class="panel checks strip[^"]*" id="checks" data-kpanel open data-running`).MatchString(b) {
		t.Fatalf("the strip is closed while fixing:\n%s", checksPanel(t, b))
	}
	if !regexp.MustCompile(`<details class="panel checks strip[^"]*" id="checks" data-kpanel open data-running`).MatchString(bobStrip) {
		t.Fatalf("bob's strip while fixing:\n%s", bobStrip)
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
	// a director may edit it, but an approved finding is not fixed
	if pd := checksPanel(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String()); fixBtnRe.FindString(pd) != "" {
		t.Fatalf("director on a complete finding:\n%s", between(pd, "<summary", "</summary>"))
	}
}

// The strip's head has room for Fix with AI in the left column: the run's
// progress and start are the state chip's title, not a text of their own.
func TestStripHeadRunInfoInTitle(t *testing.T) {
	e, _ := fixEnv(t, true)
	head := between(checksPanel(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()), "<summary", "</summary>")
	if strings.Contains(head, "runinfo") || !regexp.MustCompile(`<span class="checkstate check-done" title="1 of 1 · \d\d:\d\d">Done</span>`).MatchString(head) {
		t.Fatalf("head:\n%s", head)
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
	// nothing left: the store's message, as a toast (htmx swaps a 400 into
	// the bar's place, so an htmx press gets 422); 400 otherwise
	if rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq); rec.Code != 422 || !strings.Contains(rec.Body.String(), "run Check first") {
		t.Fatalf("again: %d %s", rec.Code, rec.Body.String())
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, nil); rec.Code != 400 {
		t.Fatalf("again, not htmx: %d %s", rec.Code, rec.Body.String())
	}
}

// While a fix runs, a failed rule's Retry is not offered (a press would be
// refused as busy).
func TestNoRetryWhileFixing(t *testing.T) {
	e := setupSerial(t)
	f := fixSetup(t, e, fooRule+"- id: scripted\n  script: check.sh\n", map[string]string{"check.sh": "cat >/dev/null; echo boom >&2; exit 3\n"}, true)
	retry := regexp.MustCompile(`<button[^>]*>Retry</button>`)
	if p := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String(); !retry.MatchString(p) {
		t.Fatalf("no Retry before:\n%s", p)
	}
	f.block = make(chan struct{})
	if rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq); rec.Code != 200 {
		t.Fatalf("fix %d %s", rec.Code, rec.Body.String())
	}
	p := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	close(f.block)
	e.srv.Store.WaitChecks()
	if retry.MatchString(p) || !strings.Contains(p, `<div class="steprow failed">`) {
		t.Fatalf("while fixing:\n%s", p)
	}
}

// Without a provider the route answers 400 with the store's words.
func TestFixRouteNoProvider(t *testing.T) {
	e, f := fixEnv(t, false)
	if rec := e.do(t, "alice", "POST", fpath+"/checks/fix", nil, hxReq); rec.Code != 422 || !strings.Contains(rec.Body.String(), "no AI provider configured") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if f.calls != 0 {
		t.Fatal("the AI was asked")
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
	retry := e.do(t, "alice", "POST", fpath+"/checks/retry", url.Values{"rule": {"no-foo"}}, hxReq)
	plain := e.do(t, "alice", "POST", fpath+"/checks", nil, nil)
	close(f.block)
	e.srv.Store.WaitChecks()
	if !strings.Contains(check, " disabled") {
		t.Errorf("Check while fixing: %q", check)
	}
	// a toast (422) for htmx presses, the bar stays; 409 otherwise
	if rec.Code != 422 || again.Code != 422 || retry.Code != 422 || plain.Code != 409 {
		t.Errorf("check %d, second fix %d, retry %d, not htmx %d", rec.Code, again.Code, retry.Code, plain.Code)
	}
	if !strings.Contains(rec.Body.String(), "running") {
		t.Errorf("check's message %q", rec.Body.String())
	}
}
