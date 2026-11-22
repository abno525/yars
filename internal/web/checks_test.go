package web

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/rules"
	"yars/internal/workflow"
)

func (e *env) rules(t *testing.T, yaml string, scripts map[string]string) {
	t.Helper()
	if len(scripts) > 0 {
		e.serialOnly(t, "rule scripts are written and run")
	}
	rd := filepath.Join(e.dir, ".yars", "rules")
	os.MkdirAll(rd, 0o755)
	os.WriteFile(filepath.Join(rd, "style.yaml"), []byte(yaml), 0o644)
	for name, body := range scripts {
		os.WriteFile(filepath.Join(rd, name), []byte("#!/bin/sh\n"+body), 0o755)
	}
	eng := rules.NewEngine(rd, e.srv.Cfg)
	e.srv.Rules = eng
	e.srv.Store.Linter = eng
}

// gateClean gives the finding a reviewer and a severity, so the workflow
// gate adds no rows to the Checks strip (D3) and only rule rows are left.
func (e *env) gateClean(t *testing.T) {
	t.Helper()
	st := e.srv.Store
	if err := st.SetReviewers("acme", fdir, []string{"bob"}, wAlice); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSeverity("acme", fdir, "high", "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
}

// checksPanel is the Checks strip (#checks, a <details> that holds the
// Dismissed <details>) of a page or fragment.
func checksPanel(t *testing.T, b string) string {
	t.Helper()
	i := strings.Index(b, `id="checks"`)
	if i < 0 {
		t.Fatalf("no checks panel:\n%s", b)
	}
	i = strings.LastIndex(b[:i], "<details")
	if i < 0 {
		t.Fatalf("the checks panel is not a <details>:\n%s", b)
	}
	depth := 0
	for j := i; ; {
		o, c := strings.Index(b[j:], "<details"), strings.Index(b[j:], "</details>")
		if c < 0 {
			t.Fatalf("checks panel not closed:\n%s", b[i:])
		}
		if o >= 0 && o < c {
			depth, j = depth+1, j+o+len("<details")
			continue
		}
		depth, j = depth-1, j+c+len("</details>")
		if depth == 0 {
			return b[i:j]
		}
	}
}

// stripTag is the Checks strip's opening tag.
func stripTag(t *testing.T, b string) string {
	t.Helper()
	p := checksPanel(t, b)
	return p[:strings.Index(p, ">")+1]
}

// D2: the strip starts closed for a viewer who is not the draft's author.
func TestChecksStripClosedByDefault(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: title-word\n  target: title\n  regex_forbid: 'injection'\n  message: Avoid the word injection\n", nil)
	tag := stripTag(t, e.do(t, "bob", "GET", fpath, nil, nil).Body.String())
	if !strings.HasPrefix(tag, `<details class="panel checks strip`) || strings.Contains(tag, " open") {
		t.Fatalf("strip for bob: %s", tag)
	}
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	if !strings.Contains(css, "summary.panelhead { cursor: pointer; list-style: none; }") || !strings.Contains(css, ".panel.checks.strip:not([open]) { height: 48px; }") {
		t.Fatal("no strip styles")
	}
	// open, the list scrolls inside the 360 px strip: a <details> wraps its
	// body in a box of its own, so the panel's flex column does not reach it
	if !strings.Contains(css, ".panel.checks.strip > .checkbody { max-height: 312px; }") {
		t.Fatal("the open strip's list does not scroll inside it")
	}
}

// D2: the author of a draft with errors finds the strip open.
func TestChecksStripOpenForAuthorWithErrors(t *testing.T) {
	e := setup(t)
	e.gateClean(t)
	e.rules(t, "- id: title-word\n  target: title\n  regex_forbid: 'injection'\n  message: Avoid the word injection\n", nil)
	if tag := stripTag(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); !strings.Contains(tag, " open") {
		t.Fatalf("strip for alice: %s", tag)
	}
	// without errors it stays closed for her too
	e.rules(t, "- id: no-zebra\n  target: title\n  regex_forbid: 'zebra'\n", nil)
	if tag := stripTag(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); strings.Contains(tag, " open") {
		t.Fatalf("clean strip for alice: %s", tag)
	}
}

// D2: while a check runs the strip is open for every viewer and says so.
func TestChecksStripOpenWhileRunning(t *testing.T) {
	e := setupSerial(t)
	flag := filepath.Join(e.dir, "go-on")
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; while [ ! -e " + flag + " ]; do sleep 0.05; done; echo '[]'\n"})
	t.Cleanup(func() {
		os.WriteFile(flag, nil, 0o644)
		e.srv.Store.WaitChecks()
	})
	if rec := e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil); rec.Code != 200 {
		t.Fatalf("start %d", rec.Code)
	}
	for _, u := range []string{"alice", "bob", "carol", "dora"} {
		tag := stripTag(t, e.do(t, u, "GET", fpath, nil, nil).Body.String())
		if !strings.Contains(tag, " open") || !strings.Contains(tag, " data-running") {
			t.Fatalf("running strip for %s: %s", u, tag)
		}
	}
	os.WriteFile(flag, nil, 0o644)
	e.srv.Store.WaitChecks()
	if tag := stripTag(t, e.do(t, "bob", "GET", fpath+"/checks", nil, nil).Body.String()); strings.Contains(tag, "data-running") || strings.Contains(tag, " open") {
		t.Fatalf("finished strip for bob: %s", tag)
	}
}

// D2: the strip sits under the finding's text.
func TestChecksStripAfterSections(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, nil)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	last := strings.LastIndex(b, `<section class="panel" id="s-`)
	if last < 0 || strings.Index(b, `id="checks"`) < last {
		t.Fatalf("checks at %d, last section at %d", strings.Index(b, `id="checks"`), last)
	}
}

// D2: no strip on a withdrawn finding, none without rules.
func TestChecksStripHiddenWhenWithdrawnOrNoRules(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, `id="checks"`) {
		t.Fatal("a strip without rules")
	}
	e.rules(t, styleRules, nil)
	if err := e.srv.Store.Transition("acme", fdir, workflow.Withdraw, "dup", wDora); err != nil {
		t.Fatal(err)
	}
	// withdrawn: an empty hidden place that keeps listening, so a live
	// withdraw removes the strip and a restore brings it back
	place := `<div id="checks" hidden hx-get="/e/acme/f/001/checks" hx-trigger="sse:check, sse:content, sse:workflow, sse:resync, sse:poll" hx-swap="outerHTML" data-sse></div>`
	for _, p := range []string{fpath, fpath + "/checks"} {
		b := e.do(t, "alice", "GET", p, nil, nil).Body.String()
		if strings.Contains(b, `class="panel checks`) || !strings.Contains(b, place) {
			t.Fatalf("%s on a withdrawn finding:\n%s", p, b)
		}
	}
	if err := e.srv.Store.Transition("acme", fdir, workflow.Revise, "", wDora); err != nil {
		t.Fatal(err)
	}
	if b := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String(); !strings.Contains(b, `<details class="panel checks strip`) {
		t.Fatalf("no strip after the restore:\n%s", b)
	}
}

// The flag beside Check in the workflow bar (Rule failed, AI checks failed,
// Checks stale) is a box of the buttons' size, 152 × 40, as Check and the
// status's buttons beside it are and as the checks panel's own state flag
// is; it was 28 px high (24 for Checks stale) and only as wide as its text.
// Config errors stay plain red text.
func TestCheckFlagAsLargeAsButtons(t *testing.T) {
	css := stylesheet(t)
	for _, want := range []string{
		".checkflag {\n  width: 152px; height: 40px; flex: none; padding: 0 10px; display: inline-flex; align-items: center; justify-content: center;",
		".checkflag.text { width: auto; height: auto;",
		".checkslot > .tag { width: 152px; height: 40px; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %q", want)
		}
	}
	// the buttons it stands beside: Check w152 at the full 40 px (no sm)
	tplHas(t, "workflow.html", `<button type="button" class="btn {{.Class}} w152" hx-post="{{.URL}}"`)
}

// rowWith is the checks table row (<tr>…</tr>) holding text.
func rowWith(t *testing.T, panel, text string) string {
	t.Helper()
	i := strings.Index(panel, text)
	if i < 0 {
		t.Fatalf("no row with %q:\n%s", text, panel)
	}
	start := strings.LastIndex(panel[:i], "<tr")
	end := strings.Index(panel[i:], "</tr>")
	return panel[start : i+end]
}

// D3: what the workflow gate asks for is a row of the strip: level error,
// place Workflow, no Dismiss.
func TestGateProblemsAreCheckRows(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: title-word\n  target: title\n  regex_forbid: 'injection'\n  message: Avoid the word injection\n", nil)
	p := checksPanel(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String())
	row := rowWith(t, p, "assign at least one reviewer")
	if !strings.Contains(row, `<span class="tag lvl-error">error</span>`) || !strings.Contains(row, ">Workflow<") || strings.Contains(row, "data-dismiss-toggle") || !strings.Contains(row, `<span class="slot w96"></span>`) {
		t.Fatalf("gate row:\n%s", row)
	}
	// before the rule rows
	if strings.Index(p, "assign at least one reviewer") > strings.Index(p, "Avoid the word injection") {
		t.Fatalf("the gate row is after a rule row:\n%s", p)
	}
	// none once the finding is past the gate's statuses
	done := setup(t)
	done.toComplete(t)
	done.rules(t, "- id: no-zebra\n  target: title\n  regex_forbid: 'zebra'\n", nil)
	if p := checksPanel(t, done.do(t, "dora", "GET", fpath, nil, nil).Body.String()); strings.Contains(p, ">Workflow<") {
		t.Fatalf("gate rows on a complete finding:\n%s", p)
	}
}

// D3: with the cvss-explained rule on, an unexplained CVSS value is one row
// (the rule's), not two.
func TestCVSSProblemListedOnce(t *testing.T) {
	e := setup(t)
	form := vecForm(nil)
	form.Set("reason_C", "because C")
	form.Set("reason_I", "because I")
	if rec := e.do(t, "alice", "POST", fpath+"/cvss", form, nil); rec.Code >= 400 {
		t.Fatalf("cvss %d: %s", rec.Code, rec.Body.String())
	}
	// cells counts the cells whose text holds s (a cell's title repeats it)
	cells := func(p, s string) int {
		return len(regexp.MustCompile(`>[^<]*`+regexp.QuoteMeta(s)+`[^<]*</td>`).FindAllString(p, -1))
	}
	e.rules(t, "- id: cv\n  check: cvss-explained\n", nil)
	p := checksPanel(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if n := cells(p, "Attack Complexity"); n != 1 {
		t.Fatalf("%d rows about Attack Complexity:\n%s", n, p)
	}
	// without the rule the gate's own row says it
	gateRow := "explain the non-standard CVSS value for Attack Complexity"
	e.rules(t, "- id: no-zebra\n  target: title\n  regex_forbid: 'zebra'\n", nil)
	p = checksPanel(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if n := cells(p, gateRow); n != 1 {
		t.Fatalf("%d gate rows about Attack Complexity:\n%s", n, p)
	}
	// a rule that only warns does not stand for the gate's error, which
	// still blocks Submit and is counted
	e.rules(t, "- id: cv\n  check: cvss-explained\n  level: warning\n", nil)
	p = checksPanel(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if !strings.Contains(p, gateRow) {
		t.Fatalf("a warning hid the gate's error:\n%s", p)
	}
	// nor does the rule's error once it is dismissed
	e.rules(t, "- id: cv\n  check: cvss-explained\n", nil)
	if rec := e.do(t, "bob", "POST", fpath+"/checks/dismiss", url.Values{"rule": {"cv"}, "target": {"cvss"}, "quote": {"AC:H"}, "reason": {"agreed"}}, nil); rec.Code != 200 {
		t.Fatalf("dismiss %d: %s", rec.Code, rec.Body.String())
	}
	p = checksPanel(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	open := p[:strings.Index(p, `<details class="dismissed"`)]
	if cells(open, gateRow) != 1 {
		t.Fatalf("a dismissed rule row hid the gate's error:\n%s", p)
	}
}

// D3: while the last run is out of date, the strip lists the rules as they
// are now, so its count, the bar's and Submit agree.
func TestStaleRunListsRulesNow(t *testing.T) {
	e := setupSerial(t)
	e.gateClean(t)
	e.rules(t, "- id: no-zebra\n  target: section:Impact\n  regex_forbid: 'zebra'\n  message: no zebra\n", nil)
	st := e.srv.Store
	check := func() {
		t.Helper()
		if rec := e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil); rec.Code != 200 {
			t.Fatalf("check %d", rec.Code)
		}
		st.WaitChecks()
	}
	submit := func(b string) string {
		t.Helper()
		wf := wfBar(t, b)
		i := strings.Index(wf, `data-action="submit"`)
		if i < 0 {
			t.Fatalf("no Submit:\n%s", wf)
		}
		return wf[i : i+strings.Index(wf[i:], ">")]
	}
	check() // clean
	// an error written after the run: listed, counted, Submit disabled
	st.UpdateSection("acme", fdir, "Impact", "A zebra.", "", e.authorOf(wAlice))
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if p := checksPanel(t, b); !strings.Contains(p, "no zebra") || !strings.Contains(p, `Errors <span class="badge">1</span>`) {
		t.Fatalf("stale strip:\n%s", p)
	}
	if !strings.Contains(wfBar(t, b), ">1 error to fix<") || !strings.Contains(submit(b), "disabled") {
		t.Fatalf("stale bar:\n%s", wfBar(t, b))
	}
	// a run that found it, then the fix: nothing listed, Submit enabled
	check()
	st.UpdateSection("acme", fdir, "Impact", "A horse.", "", e.authorOf(wAlice))
	b = e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if p := checksPanel(t, b); strings.Contains(p, "no zebra") || !strings.Contains(p, `Errors <span class="badge0">0</span>`) {
		t.Fatalf("stale strip after the fix:\n%s", p)
	}
	if strings.Contains(wfBar(t, b), "to fix") || strings.Contains(submit(b), "disabled") {
		t.Fatalf("stale bar after the fix:\n%s", wfBar(t, b))
	}
}

// D3: an error the last run found on this content (a script rule's) is
// counted, and Submit, which runs every rule, waits for it too.
func TestRunErrorDisablesSubmit(t *testing.T) {
	e := setupSerial(t)
	e.gateClean(t)
	e.rules(t, "- id: scr\n  script: check.sh\n", map[string]string{"check.sh": `cat >/dev/null; echo '[{"message":"script says no","target":"section:Impact"}]'` + "\n"})
	e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	e.srv.Store.WaitChecks()
	wf := wfBar(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	i := strings.Index(wf, `data-action="submit"`)
	if !strings.Contains(wf, ">1 error to fix<") || i < 0 || !strings.Contains(wf[i:i+strings.Index(wf[i:], ">")], "disabled") {
		t.Fatalf("bar with a run's error:\n%s", wf)
	}
}

// D3: in verification the bar's "errors open" is the strip's Errors count
// (the gate's rows included).
func TestErrorsOpenCountMatchesStrip(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	form := vecForm(nil)
	form.Set("reason_C", "because C")
	form.Set("reason_I", "because I")
	if rec := e.do(t, "alice", "POST", fpath+"/cvss", form, nil); rec.Code >= 400 {
		t.Fatalf("cvss %d: %s", rec.Code, rec.Body.String())
	}
	e.rules(t, "- id: title-word\n  target: title\n  regex_forbid: 'injection'\n  message: Avoid the word injection\n", nil)
	b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	if p := checksPanel(t, b); !strings.Contains(p, `Errors <span class="badge">2</span>`) {
		t.Fatalf("strip:\n%s", p)
	}
	if wf := wfBar(t, b); !strings.Contains(wf, ">2 errors open<") {
		t.Fatalf("bob's bar:\n%s", wf)
	}
}

// D2: the browser keeps the user's choice per finding, never against a run.
func TestAppJSRemembersChecksStrip(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	if !strings.Contains(js, "yars-checks:") || !strings.Contains(js, "data-running") {
		t.Fatal("app.js does not remember the strip")
	}
	// a press of a button in the head (Fix with AI) is not the user's choice
	if !strings.Contains(js, "if (!s || evt.target.closest('button')) return;") {
		t.Fatal("a button in the strip's head counts as opening or closing it")
	}
	// an empty Dismiss row left in a closed strip does not hold its refreshes
	// (a typed reason still does)
	if !strings.Contains(js, "(t.id === 'checks' && t.open && !!t.querySelector('.dismissrow:not([hidden])'))") {
		t.Fatal("a closed strip's refreshes wait for a hidden Dismiss row")
	}
}

const styleRules = `
- id: title-word
  target: title
  regex_forbid: 'injection'
  message: Avoid the word injection
- id: scripted
  script: check.sh
  level: warning
`

func TestChecksPanel(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": `cat >/dev/null; sleep 0.3; echo '[{"message":"script says hi","quote":"q1","target":"section:Impact"}]'` + "\n"})
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	p := checksPanel(t, b)
	if !strings.Contains(p, "Avoid the word injection") || strings.Contains(p, "script says hi") {
		t.Fatalf("checks panel (fast only):\n%s", p)
	}
	// the bar counts the rule's error with the gate's two (D3) and lists none
	if wf := wfBar(t, b); !strings.Contains(wf, ">3 errors to fix<") || strings.Contains(wf, "Avoid the word injection") {
		t.Fatalf("workflow bar and rule errors:\n%s", wf)
	}
	// the panel refetches itself on check events
	// workflow events too: the gate's rows (reviewers, status) are listed here (D3)
	if !strings.Contains(p, `hx-get="/e/acme/f/001/checks"`) || !strings.Contains(p, "sse:check") || !strings.Contains(p, "sse:workflow") || !strings.Contains(p, "data-sse") {
		t.Fatalf("no live refresh:\n%s", p)
	}
	// the Check button sits in the workflow bar, before Submit
	wf := wfBar(t, b)
	if !regexp.MustCompile(`<button[^>]*class="btn secondary w152"[^>]*>[^<]*<svg[^>]*>.*</svg>Check</button>`).MatchString(wf) ||
		strings.Index(wf, ">Check</button>") > strings.Index(wf, ">Submit</button>") {
		t.Fatalf("no Check button before Submit in the bar:\n%s", wf)
	}
	if strings.Contains(p, ">Check</button>") {
		t.Fatal("Check button still in the checks panel")
	}
	// started: the bar answers, running, and the panel comes along
	rec := e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	run := rec.Body.String()
	if rec.Code != 200 || !regexp.MustCompile(`<button[^>]*class="btn secondary w152 checking"[^>]*disabled[^>]*>.*Checking <span class="mono">\d/2</span><progress value="\d" max="2"></progress></button>`).MatchString(run) {
		t.Fatalf("running bar %d:\n%s", rec.Code, run)
	}
	if !strings.Contains(run, `id="workflow"`) || !strings.Contains(run, `hx-swap-oob="true"`) || !strings.Contains(run, `class="checkstate check-running"`) {
		t.Fatalf("bar with the panel out of band:\n%s", run)
	}
	e.srv.Store.WaitChecks()
	done := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	if !strings.Contains(done, "script says hi") || !strings.Contains(done, "q1") || !strings.Contains(done, ">Impact<") {
		t.Fatalf("finished panel:\n%s", done)
	}
	// the state flag is the Check button's size (152 × 40), in a slot as wide
	if !strings.Contains(done, `<span class="slot w152"><span class="checkstate check-done"`) {
		t.Fatalf("done state:\n%s", done)
	}
	if bar := e.do(t, "alice", "GET", fpath+"/workflow", nil, nil).Body.String(); !regexp.MustCompile(`class="btn secondary w152"[^>]*>.*Check</button>`).MatchString(bar) {
		t.Fatalf("idle Check button:\n%s", bar)
	}
	// the violations were posted to the chat as check comments
	chat := e.do(t, "alice", "GET", fpath+"/chat", nil, nil).Body.String()
	if !strings.Contains(chat, "script says hi") || !strings.Contains(chat, "Avoid the word injection") {
		t.Fatalf("chat:\n%s", chat)
	}
}

// A started run's answer (bar plus panel, running) fetches both again once
// swapped in: check events that came while the POST was in flight (a fast
// run's last one) would otherwise be lost and leave them at Running.
func TestChecksStartedRefetchOnLoad(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": `cat >/dev/null; sleep 0.3; echo '[]'` + "\n"})
	run := e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil).Body.String()
	trig := regexp.MustCompile(`id="(workflow|checks)"[^>]*hx-trigger="([^"]*)"`)
	got := map[string]string{}
	for _, m := range trig.FindAllStringSubmatch(run, -1) {
		got[m[1]] = m[2]
	}
	for _, id := range []string{"workflow", "checks"} {
		if !strings.HasSuffix(got[id], ", load") {
			t.Errorf("started %s does not refetch on load: %q", id, got[id])
		}
	}
	e.srv.Store.WaitChecks()
	for _, p := range []string{fpath + "/checks", fpath + "/workflow"} {
		if b := e.do(t, "alice", "GET", p, nil, nil).Body.String(); strings.Contains(b, ", load\"") {
			t.Errorf("%s refetches on load (a loop):\n%s", p, b)
		}
	}
}

// holdLinter holds each check run (every rule kind) until release closes;
// the fast rules for the page pass at once.
type holdLinter struct {
	release chan struct{}
	in      atomic.Int32
}

func (l *holdLinter) Lint(_ context.Context, _ *finding.Finding, k rules.Kind) []rules.Violation {
	if k == rules.All {
		l.in.Add(1)
		<-l.release
	}
	return nil
}

// Q3: over checks.max_running a run waits: the strip says Queued in its
// state slot and the bar's Check button says so in its place; once the slot
// frees it runs and ends.
func TestChecksStripQueued(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: title-word\n  target: title\n  regex_forbid: 'injection'\n  message: Avoid the word injection\n", nil)
	st := e.srv.Store
	c := st.Config()
	c.Checks.MaxRunning = 1
	st.SetConfig(c)
	l := &holdLinter{release: make(chan struct{})}
	st.Linter = l
	released := false
	release := func() {
		if !released {
			released = true
			close(l.release)
		}
		st.WaitChecks()
	}
	t.Cleanup(release)
	other, err := st.CreateFinding("acme", "Reflected XSS", e.authorOf(wAlice))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.StartCheck("acme", other.Dir, wAlice); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); l.in.Load() != 1; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the first run did not start")
		}
	}
	rec := e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	run := rec.Body.String()
	if rec.Code != 200 || !regexp.MustCompile(`<button[^>]*class="btn secondary w152 checking"[^>]*disabled[^>]*>.*</svg>Queued<progress value="0" max="1"></progress></button>`).MatchString(run) {
		t.Fatalf("queued bar %d:\n%s", rec.Code, run)
	}
	slot := regexp.MustCompile(`<span class="slot w152"><span class="checkstate check-queued" title="[^"]*">Queued</span></span>`)
	if !slot.MatchString(run) {
		t.Fatalf("queued strip in the answer:\n%s", run)
	}
	p := e.do(t, "bob", "GET", fpath+"/checks", nil, nil).Body.String()
	if tag := stripTag(t, p); !slot.MatchString(p) || !strings.Contains(tag, " open") || !strings.Contains(tag, " data-running") {
		t.Fatalf("queued strip:\n%s", p)
	}
	release()
	p = e.do(t, "bob", "GET", fpath+"/checks", nil, nil).Body.String()
	if strings.Contains(p, "Queued") || !strings.Contains(p, `<span class="slot w152"><span class="checkstate check-done"`) {
		t.Fatalf("after the slot freed:\n%s", p)
	}
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	if !strings.Contains(css, ".checkstate.check-running, .checkstate.check-queued {") {
		t.Fatal("no queued state style")
	}
}

func TestChecksPanelLayout(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": `cat >/dev/null; echo '[{"message":"warn","quote":"q"}]'` + "\n"})
	e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	e.srv.Store.WaitChecks()
	p := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	if strings.Contains(p, "style=") {
		t.Fatalf("inline style:\n%s", p)
	}
	if !strings.Contains(p, `class="slot w152"`) || !strings.Contains(p, "<thead>") {
		t.Fatalf("status slot / headers:\n%s", p)
	}
	// alice (pentester) may dismiss the warning, not the error: the error's
	// button keeps its place
	if strings.Count(p, "data-dismiss-toggle") != 1 || !strings.Contains(p, `<span class="slot w96"></span>`) {
		t.Fatalf("dismiss buttons for alice:\n%s", p)
	}
	if !regexp.MustCompile(`class="btn [^"]*w96"`).MatchString(p) {
		t.Fatalf("dismiss width:\n%s", p)
	}
	// Dismiss opens a reason form: Reason, Cancel, Dismiss (error: Dismiss error)
	if !strings.Contains(p, `name="reason"`) || !strings.Contains(p, `class="btn save sm w120" aria-keyshortcuts="Control+Enter">Dismiss</button>`) || !strings.Contains(p, "data-dismiss-cancel") {
		t.Fatalf("reason form:\n%s", p)
	}
	pb := e.do(t, "bob", "GET", fpath+"/checks", nil, nil).Body.String()
	if strings.Count(pb, "data-dismiss-toggle") != 2 || !strings.Contains(pb, `>Dismiss error</button>`) {
		t.Fatalf("dismiss buttons for bob:\n%s", pb)
	}
	// each rule of the run has a row: id, kind, state
	steps := regexp.MustCompile(`<div class="steprow[^"]*">`).FindAllString(p, -1)
	if len(steps) != 2 || !strings.Contains(p, `<span class="ruleid" title="title-word">title-word</span>`) || !strings.Contains(p, `<span class="kt">Script</span>`) {
		t.Fatalf("step rows:\n%s", p)
	}
	if !strings.Contains(p, `<span class="badge">1</span>`) {
		t.Fatalf("counts:\n%s", p)
	}
}

// R5: a checks panel without result rows is as high as what it shows (no
// empty space under its dash row); one with rows keeps its fixed height.
func TestChecksEmptyPanelHasNoSpaceBelow(t *testing.T) {
	e := setupSerial(t)
	e.gateClean(t)
	e.rules(t, "- id: no-zebra\n  target: title\n  regex_forbid: 'zebra'\n", nil)
	p := checksPanel(t, e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String())
	if !strings.Contains(p, `<details class="panel checks strip empty" id="checks"`) {
		t.Fatalf("empty panel:\n%s", p)
	}
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	if !regexp.MustCompile(`(?m)^\.panel\.checks\.empty \{ height: auto; max-height: 360px; \}`).MatchString(css) {
		t.Fatal("no auto height for the empty checks panel")
	}
	e.rules(t, styleRules, nil)
	if p := checksPanel(t, e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()); !strings.Contains(p, `<details class="panel checks strip" id="checks"`) {
		t.Fatalf("panel with rows:\n%s", p)
	}
}

// The same wording found twice in one place is one row: one Dismiss covers
// it and the count says so (D18).
func TestChecksCountsMatchRows(t *testing.T) {
	e := setupSerial(t)
	e.gateClean(t)
	e.rules(t, "- id: letter-i\n  target: title\n  regex_forbid: 'i'\n  message: no letter i\n", nil)
	p := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	if n := strings.Count(p, `<span class="tag lvl-error">`); n != 1 || !strings.Contains(p, `Errors <span class="badge">1</span>`) {
		t.Fatalf("%d rows for one place:\n%s", n, p)
	}
	// the workflow bar counts it once too (D3: it lists nothing itself)
	if wf := wfBar(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); !strings.Contains(wf, ">1 error to fix<") {
		t.Fatalf("bar count:\n%s", wf)
	}
	st := e.srv.Store
	st.SetReviewers("acme", "F-001-sql-injection", []string{"bob"}, wAlice)
	st.UpdateSeverity("acme", "F-001-sql-injection", "high", "", e.authorOf(wAlice))
	if err := st.Transition("acme", "F-001-sql-injection", workflow.Submit, "", wAlice); err == nil || strings.Count(err.Error(), "no letter i") != 1 {
		t.Fatalf("submit refusal: %v", err)
	}
}

// A notice about the rules (the AI skipped) is neither a row nor counted
// (the gate does not count it either): its rule's step says it.
func TestChecksNoticeNotCounted(t *testing.T) {
	e := setupSerial(t)
	e.gateClean(t)
	e.rules(t, "- id: letter-i\n  target: title\n  regex_forbid: 'i'\n  message: no letter i\n", nil)
	ref, err := e.srv.Store.Finding("acme", "F-001-sql-injection")
	if err != nil {
		t.Fatal(err)
	}
	d := e.srv.Store.DB()
	skipped := "AI rules skipped: no AI provider configured"
	id, _ := d.StartRun("acme", ref.F.Meta.ID, ref.Hash, "bob", "")
	d.AddSteps([]db.CheckStep{{RunID: id, Pos: 0, Rule: "letter-i", Kind: "pattern", State: db.StepHits, Hits: 1}, {RunID: id, Pos: 1, Rule: "ai-x", Kind: "ai", State: db.StepFailed, Message: skipped}})
	d.TxFor("acme", func(tx *db.Tx) error {
		return tx.FinishRun(id, db.RunDone, "", []db.CheckResult{
			{Rule: "ai-x", Level: "warning", Message: skipped, Target: "ai", QuoteHash: "n"},
			{Rule: "letter-i", Level: "error", Message: "no letter i", Target: "title", Quote: "i", QuoteHash: db.ViolationHash("title", "i")},
		})
	})
	p := e.do(t, "bob", "GET", fpath+"/checks", nil, nil).Body.String()
	if strings.Contains(p, `lvl-warning`) || !strings.Contains(p, `Warnings <span class="badge0">0</span>`) || !strings.Contains(p, "AI checks failed") {
		t.Fatalf("notice counted or listed:\n%s", p)
	}
	if strings.Count(p, "data-dismiss-toggle") != 1 || strings.Contains(p, `<span class="slot w96"></span>`) {
		t.Fatalf("rows without Dismiss:\n%s", p)
	}
	if wf := e.do(t, "bob", "GET", fpath+"/workflow", nil, nil).Body.String(); strings.Contains(wf, "warning") {
		t.Fatalf("bar counts the notice:\n%s", wf)
	}
}

func TestChecksDismiss(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	form := url.Values{"rule": {"title-word"}, "quote": {"injection"}, "reason": {"Injection is the client's term"}}
	if rec := e.do(t, "alice", "POST", fpath+"/checks/dismiss", form, nil); rec.Code != 403 {
		t.Fatalf("pentester dismissed an error: %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks/dismiss", url.Values{"rule": {"nope"}, "quote": {"x"}, "reason": {"x"}}, nil); rec.Code != 400 {
		t.Fatalf("unknown violation: %d", rec.Code)
	}
	// a reason is required
	if rec := e.do(t, "bob", "POST", fpath+"/checks/dismiss", url.Values{"rule": {"title-word"}, "quote": {"injection"}, "reason": {"  "}}, nil); rec.Code != 400 {
		t.Fatalf("dismiss without a reason: %d", rec.Code)
	}
	rec := e.do(t, "bob", "POST", fpath+"/checks/dismiss", form, nil)
	if rec.Code != 200 {
		t.Fatalf("reviewer dismiss %d: %s", rec.Code, rec.Body.String())
	}
	p := rec.Body.String()
	if !strings.Contains(p, "Dismissed") || !strings.Contains(p, ">bob<") || !strings.Contains(p, `<details class="dismissed"`) ||
		!strings.Contains(p, "<th class=\"c-reason\">Reason</th>") || !strings.Contains(p, "Injection is the client&#39;s term") {
		t.Fatalf("dismissed row:\n%s", p)
	}
	// the bar no longer counts it: the gate's two are left (D3)
	if wf := wfBar(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); !strings.Contains(wf, ">2 errors to fix<") {
		t.Fatalf("dismissed error still counted:\n%s", wf)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks/undismiss", form, nil); rec.Code != 403 {
		t.Fatalf("pentester restored an error: %d", rec.Code)
	}
	rec = e.do(t, "dora", "POST", fpath+"/checks/undismiss", form, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), `<details class="dismissed"`) {
		t.Fatalf("undismiss %d:\n%s", rec.Code, rec.Body.String())
	}
}

// Violations without a quote are dismissed one place at a time.
func TestChecksDismissEmptyQuoteByTarget(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, "- id: scripted\n  script: check.sh\n  level: warning\n", map[string]string{"check.sh": `cat >/dev/null; echo '[{"message":"Host empty","target":"details:Host"},{"message":"Port empty","target":"details:Port"}]'` + "\n"})
	e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	e.srv.Store.WaitChecks()
	p := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	if !strings.Contains(p, `name="target" value="details:Host"`) {
		t.Fatalf("no target in the dismiss form:\n%s", p)
	}
	form := url.Values{"rule": {"scripted"}, "target": {"details:Host"}, "quote": {""}, "reason": {"n/a"}}
	rec := e.do(t, "alice", "POST", fpath+"/checks/dismiss", form, nil)
	if rec.Code != 200 {
		t.Fatalf("dismiss %d: %s", rec.Code, rec.Body.String())
	}
	p = rec.Body.String()
	i := strings.Index(p, `<details class="dismissed"`)
	if i < 0 || !strings.Contains(p[:i], "Port empty") || strings.Contains(p[:i], "Host empty") || !strings.Contains(p[i:], "Host empty") {
		t.Fatalf("one dismissal hid both:\n%s", p)
	}
	rec = e.do(t, "alice", "POST", fpath+"/checks/undismiss", form, nil)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), `<details class="dismissed"`) {
		t.Fatalf("undismiss %d:\n%s", rec.Code, rec.Body.String())
	}
}

// Running the checks again posts nothing for known violations, and a fixed
// one leaves no line in the chat.
func TestChecksRerunPostsNothing(t *testing.T) {
	e := setupSerial(t)
	script := map[string]string{"check.sh": `cat >/dev/null; echo '[{"message":"script says hi","quote":"q1","target":"section:Impact"}]'` + "\n"}
	e.rules(t, "- id: scripted\n  script: check.sh\n  level: warning\n", script)
	run := func() string {
		t.Helper()
		e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
		e.srv.Store.WaitChecks()
		return e.do(t, "alice", "GET", fpath+"/chat?all=1", nil, nil).Body.String()
	}
	first := run()
	const msg = "<p>script says hi</p>"
	if strings.Count(first, msg) != 1 {
		t.Fatalf("first run chat:\n%s", first)
	}
	if again := run(); strings.Count(again, msg) != 1 {
		t.Fatalf("second run chat:\n%s", again)
	}
	e.rules(t, "- id: scripted\n  script: check.sh\n  level: warning\n", map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	fixed := run()
	if strings.Contains(fixed, "found a check fixed") || strings.Count(fixed, msg) != 1 {
		t.Fatalf("fixed run chat:\n%s", fixed)
	}
}

func TestChecksStaleAndInvalid(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo not json\n"})
	e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	e.srv.Store.WaitChecks()
	p := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	if !strings.Contains(p, `class="checkstate check-invalid"`) || !strings.Contains(p, "Invalid output") {
		t.Fatalf("invalid state:\n%s", p)
	}
	if err := e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Impact", "changed", "", gitrepo.Author{Name: "x", Email: "x@x"}); err != nil {
		t.Fatal(err)
	}
	p = e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	if !strings.Contains(p, `class="checkstate check-stale"`) {
		t.Fatalf("stale state:\n%s", p)
	}
}

// wfBar is the workflow bar (#workflow) of a page.
func wfBar(t *testing.T, b string) string {
	t.Helper()
	i := strings.Index(b, `id="workflow"`)
	if i < 0 {
		t.Fatalf("no workflow bar:\n%s", b)
	}
	j := strings.Index(b[i:], "</section>")
	return b[i : i+j]
}

// Each rule of a run is a row: Pass, hits, or failed with Retry; Retry runs
// that rule again. The bar flags a failed rule, and stale checks.
func TestCheckStepRowsAndRetry(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo boom >&2; exit 3\n"})
	e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	e.srv.Store.WaitChecks()
	p := e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	if !strings.Contains(p, `<div class="steprow failed">`) || !strings.Contains(p, "rule failed: boom") {
		t.Fatalf("failed step:\n%s", p)
	}
	if !regexp.MustCompile(`<button class="btn secondary sm w80"[^>]*>Retry</button>`).MatchString(p) || !strings.Contains(p, `name="rule" value="scripted"`) {
		t.Fatalf("no Retry:\n%s", p)
	}
	if !strings.Contains(p, `<span class="stepstate hits" title="1 error">1 error</span>`) {
		t.Fatalf("hits step:\n%s", p)
	}
	if bar := wfBar(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String()); !strings.Contains(bar, `<span class="checkflag bad">Rule failed <span class="mono">1</span></span>`) {
		t.Fatalf("bar flag:\n%s", bar)
	}
	// fixed script: Retry runs it alone, the panel shows it passing
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	rec := e.do(t, "alice", "POST", fpath+"/checks/retry", url.Values{"rule": {"scripted"}}, nil)
	if rec.Code != 200 {
		t.Fatalf("retry %d %s", rec.Code, rec.Body.String())
	}
	e.srv.Store.WaitChecks()
	p = e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String()
	if strings.Contains(p, "steprow failed") || !strings.Contains(p, `<span class="stepstate pass" title="Pass">Pass</span>`) {
		t.Fatalf("after retry:\n%s", p)
	}
	if !regexp.MustCompile(`<span class="steptime mono">\d+(\.\d)? s</span>`).MatchString(p) {
		t.Fatalf("script timing:\n%s", p)
	}
	if rec := e.do(t, "alice", "POST", fpath+"/checks/retry", url.Values{"rule": {"nope"}}, nil); rec.Code != 400 {
		t.Fatalf("retry unknown rule %d", rec.Code)
	}
	// an edit makes the checks stale: the bar says so, Check is primary
	e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Impact", "changed", "", gitrepo.Author{Name: "x", Email: "x@x"})
	bar := wfBar(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if !strings.Contains(bar, `<span class="tag check-stale">Checks stale</span>`) || !strings.Contains(bar, `class="btn primary w152"`) {
		t.Fatalf("stale bar:\n%s", bar)
	}
	if strings.Contains(bar, "style=") {
		t.Fatal("inline style")
	}
}

func TestChecksProgressEvents(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	sub := e.srv.Events.Subscribe("acme", "", 64)
	defer e.srv.Events.Unsubscribe(sub)
	e.do(t, "alice", "POST", fpath+"/checks", url.Values{}, nil)
	e.srv.Store.WaitChecks()
	n := 0
	for len(sub.C()) > 0 {
		if ev := <-sub.C(); ev.Kind == "check" && ev.Fid == "F-001" {
			n++
		}
	}
	if n < 4 { // started, 0/2, 1/2, 2/2, finished
		t.Fatalf("%d check events", n)
	}
}

func TestPreviewShowsHints(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, "- id: impact-bt\n  target: section:Impact\n  regex_forbid: '`'\n  message: No backticks in Impact\n", nil)
	edit := e.do(t, "alice", "GET", fpath+"/s/Impact/edit", nil, nil).Body.String()
	var pv string
	for _, part := range strings.Split(edit, `hx-post="`)[1:] {
		u := part[:strings.Index(part, `"`)]
		if strings.Contains(u, "/preview") {
			pv = strings.ReplaceAll(u, "&amp;", "&")
		}
	}
	if pv == "" || !strings.Contains(pv, "s=Impact") {
		t.Fatalf("preview url %q", pv)
	}
	b := e.do(t, "alice", "POST", pv, url.Values{"body": {"uses `x`"}}, nil).Body.String()
	if !strings.Contains(b, "No backticks in Impact") {
		t.Fatalf("no hint:\n%s", b)
	}
}
