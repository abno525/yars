package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/workflow"
)

// The accounts of setupSimple, as the store sees them.
var (
	sAnna = config.User{Username: "anna", Role: "director", IsAdmin: true}
	sBen  = config.User{Username: "ben", Role: "director"}
)

// ready gives the simple env's finding a severity, so Complete's gate is
// clean.
func (e *env) ready(t *testing.T) {
	t.Helper()
	if err := e.srv.Store.UpdateSeverity("acme", fdir, "high", "", sAnna); err != nil {
		t.Fatal(err)
	}
}

// toCompleteSimple completes the simple env's finding as anna.
func (e *env) toCompleteSimple(t *testing.T) {
	t.Helper()
	e.ready(t)
	if err := e.srv.Store.Transition("acme", fdir, workflow.Complete, "", sAnna); err != nil {
		t.Fatal(err)
	}
}

// seenForm is what user's bar sends with Complete: the content and the
// attachments the page showed.
func (e *env) seenForm(t *testing.T, user string) url.Values {
	t.Helper()
	m := regexp.MustCompile(`<input type="hidden" name="seen" value="([0-9a-f]+)"><input type="hidden" name="seenfiles" value="([0-9a-f]+)">`).FindStringSubmatch(wfBar(t, e.do(t, user, "GET", fshort, nil, nil).Body.String()))
	if m == nil {
		t.Fatalf("%s's bar sends no viewed version", user)
	}
	return url.Values{"seen": {m[1]}, "seenfiles": {m[2]}}
}

// checkedSimple runs Check on the finding as ben and waits for it (Require
// Check, on by default once rules are set, wants a run to complete).
func (e *env) checkedSimple(t *testing.T) {
	t.Helper()
	if _, err := e.srv.Store.StartCheck("acme", fdir, sBen); err != nil {
		t.Fatal(err)
	}
	e.srv.Store.WaitChecks()
}

// stepsOf is the bar's step list.
func stepsOf(t *testing.T, b string) string {
	t.Helper()
	wf := wfBar(t, b)
	i, j := strings.Index(wf, `<ol class="steps">`), strings.Index(wf, "</ol>")
	if i < 0 || j < i {
		t.Fatalf("no steps:\n%s", wf)
	}
	return wf[i:j]
}

// The simple bar's steps are draft, complete and reported: no verification
// and no signed off; the current one moves along, and a withdrawn finding
// has none current.
func TestSimpleStepBar(t *testing.T) {
	e := setupSimple(t)
	steps := func() string { return stepsOf(t, e.do(t, "anna", "GET", fshort, nil, nil).Body.String()) }
	for _, c := range []struct {
		do   func()
		want string
	}{
		{func() {}, `<li class="step current">draft</li><li class="step">complete</li><li class="step">reported</li>`},
		{func() { e.toCompleteSimple(t) }, `<li class="step done">draft</li><li class="step current">complete</li><li class="step">reported</li>`},
		{func() {
			if err := e.srv.Store.Transition("acme", fdir, workflow.Report, "", sAnna); err != nil {
				t.Fatal(err)
			}
		}, `<li class="step done">draft</li><li class="step done">complete</li><li class="step current">reported</li>`},
		{func() {
			if err := e.srv.Store.Transition("acme", fdir, workflow.Withdraw, "duplicate", sAnna); err != nil {
				t.Fatal(err)
			}
		}, `<li class="step">draft</li><li class="step">complete</li><li class="step">reported</li>`},
	} {
		c.do()
		got := steps()
		if !strings.Contains(got, c.want) || strings.Contains(got, "verification") || strings.Contains(got, "signed off") {
			t.Fatalf("status %s: steps\n%s\nwant %s", e.status(t), got, c.want)
		}
	}
}

// A draft's bar holds Complete (primary, Shift+A) in Submit's slot and
// Withdraw at the right edge, for the author and for anyone else (every
// account completes); Complete sends the version the page showed, as Sign
// off and Approve do. No review action is drawn.
func TestSimpleDraftSlots(t *testing.T) {
	e := setupSimple(t)
	e.ready(t)
	complete := `<button class="btn w112 primary" id="wf-complete" aria-keyshortcuts="Shift&#43;A" data-action="complete" title="Complete">Complete</button>`
	withdraw := `<button type="button" class="btn w136 danger" id="wf-withdraw" aria-keyshortcuts="Shift&#43;W" data-slot="withdraw" data-action="withdraw" title="Withdraw" aria-controls="wf-withdraw-reason" aria-expanded="false" data-reason-toggle>Withdraw</button>`
	seen := regexp.MustCompile(`<form method="post" action="/e/acme/f/001/action/complete" class="wf-action" data-slot="complete"><input type="hidden" name="seen" value="[0-9a-f]+"><input type="hidden" name="seenfiles" value="[0-9a-f]+"><button`)
	for _, u := range []string{"anna", "ben"} {
		for _, path := range []string{fshort, fshort + "/workflow"} {
			wf := wfBar(t, e.do(t, u, "GET", path, nil, nil).Body.String())
			if !strings.Contains(wf, complete) || !strings.Contains(wf, withdraw) || strings.Index(wf, complete) > strings.Index(wf, withdraw) {
				t.Fatalf("%s %s: no Complete then Withdraw:\n%s", u, path, wf)
			}
			if !seen.MatchString(wf) {
				t.Fatalf("%s %s: Complete sends no viewed version:\n%s", u, path, wf)
			}
			for _, act := range []string{"submit", "return", "clear", "approve", "take_back"} {
				if strings.Contains(wf, `data-action="`+act+`"`) || strings.Contains(wf, `id="wf-`+act+`"`) {
					t.Fatalf("%s %s: %s drawn:\n%s", u, path, act, wf)
				}
			}
		}
	}
}

// Complete from the page: the bar's form takes the draft to complete; the
// chat says "completed it" and the history "completed", in green; the
// revert says it goes back to draft. A version the page did not show is
// refused, as a sign-off of it is.
func TestSimpleCompleteFromPage(t *testing.T) {
	e := setupSimple(t)
	e.ready(t)
	form := e.seenForm(t, "ben")
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "Changed while ben read.", "", sAnna); err != nil {
		t.Fatal(err)
	}
	if b := e.denied(t, "ben", fshort+"/action/complete", form); !strings.Contains(b, "the finding changed since you opened it; read it again") || e.status(t) != "draft" {
		t.Fatalf("stale Complete: status %s", e.status(t))
	}
	rec := e.do(t, "ben", "POST", fshort+"/action/complete", e.seenForm(t, "ben"), nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != fshort || e.status(t) != "complete" {
		t.Fatalf("complete: code %d to %q, status %s", rec.Code, rec.Header().Get("Location"), e.status(t))
	}
	if got := e.events(t); got != "ben:complete" {
		t.Fatalf("events %q", got)
	}
	if rec := e.do(t, "anna", "POST", fshort+"/action/reopen", url.Values{"reason": {"missed a step"}}, nil); rec.Code != http.StatusSeeOther || e.status(t) != "draft" {
		t.Fatalf("revert: code %d, status %s", rec.Code, e.status(t))
	}
	b := e.do(t, "anna", "GET", fshort, nil, nil).Body.String()
	for _, want := range []string{
		`<div class="chatev ev-complete"><span class="what"><strong>ben</strong> completed it</span>`,
		`<div class="chatev ev-reopen"><span class="what"><strong>anna</strong> reverted it to draft: <span class="text">missed a step</span></span>`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("chat lacks %s", want)
		}
	}
	h := e.do(t, "anna", "GET", fshort+"/history?show=status", nil, nil).Body.String()
	for _, want := range []string{
		`<span class="dot ev-complete"></span>`,
		`<strong>ben</strong> <span class="evact">completed</span>`,
		`<strong>anna</strong> <span class="evact">reverted to draft</span>`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("history lacks %s", want)
		}
	}
	css := e.do(t, "anna", "GET", "/static/style.css", nil, nil).Body.String()
	for _, want := range []string{
		".chatev.ev-clear::before, .chatev.ev-approve::before, .chatev.ev-complete::before { background: var(--green); }",
		".dot.ev-clear, .dot.ev-approve, .dot.ev-complete { background: var(--green); }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %q", want)
		}
	}
}

// The standard chat and history keep their words: a revert there goes back
// to verification, and the review events read as before in both.
func TestStandardEventWords(t *testing.T) {
	for _, c := range []struct {
		ev     string
		simple bool
		chat   string
		hist   string
	}{
		{"reopen", false, "reverted it to verification", "reverted to verification"},
		{"approve", false, "approved it", "approved"},
		{"unreport", true, "reverted it to complete", "reverted to complete"},
		{"complete", true, "completed it", "completed"},
		{"bogus", true, "bogus", "bogus"},
	} {
		if got := eventTextFor(c.ev, c.simple); got != c.chat {
			t.Errorf("chat %s (simple %v): %q", c.ev, c.simple, got)
		}
		if got := eventLabelFor(c.ev, c.simple); got != c.hist {
			t.Errorf("history %s (simple %v): %q", c.ev, c.simple, got)
		}
	}
}

// Complete waits for the content gate: without a severity it is disabled,
// the state says what to fix, and a post is refused with the reason.
func TestSimpleCompleteDisabledByGate(t *testing.T) {
	e := setupSimple(t)
	wf := wfBar(t, e.do(t, "anna", "GET", fshort, nil, nil).Body.String())
	if !strings.Contains(wf, `id="wf-complete" aria-keyshortcuts="Shift&#43;A" data-action="complete" disabled title="Complete" aria-describedby="wf-state">Complete</button>`) {
		t.Fatalf("Complete not disabled:\n%s", wf)
	}
	if !strings.Contains(wf, `<span class="wfstate error" id="wf-state" title="1 error to fix">1 error to fix</span>`) {
		t.Fatalf("state:\n%s", wf)
	}
	if strings.Contains(wf, "reviewer") {
		t.Fatalf("the gate asks for a reviewer:\n%s", wf)
	}
	if b := e.denied(t, "anna", fshort+"/action/complete", e.seenForm(t, "anna")); !strings.Contains(b, "cannot complete: set a CVSS vector or a severity") || e.status(t) != "draft" {
		t.Fatalf("posted: status %s", e.status(t))
	}
}

// Complete is held by every open check, a warning too, and with Require
// Check on (the default once rules are set) by a missing run on this
// content: disabled, with the state saying why.
func TestSimpleCompleteOpenChecks(t *testing.T) {
	e := setupSimple(t)
	e.rules(t, softRule, nil)
	e.ready(t)
	page := func() string { return e.do(t, "anna", "GET", fshort, nil, nil).Body.String() }
	b := page()
	if btn := slotButton(t, b, "complete"); !strings.Contains(btn, " disabled") || !strings.Contains(wfBar(t, b), ">1 warning open<") {
		t.Fatalf("an open warning:\n%s", wfBar(t, b))
	}
	if err := e.srv.Store.Dismiss("acme", fdir, "soft", "SQL", sAnna); err != nil {
		t.Fatal(err)
	}
	b = page()
	if btn := slotButton(t, b, "complete"); !strings.Contains(btn, " disabled") || !strings.Contains(btn, `aria-describedby="wf-state"`) || !strings.Contains(wfBar(t, b), ">Run Check first<") {
		t.Fatalf("no run:\n%s", wfBar(t, b))
	}
	e.checkedSimple(t)
	b = page()
	if btn := slotButton(t, b, "complete"); strings.Contains(btn, " disabled") || strings.Contains(wfBar(t, b), "Run Check first") {
		t.Fatalf("checked and clean:\n%s", wfBar(t, b))
	}
	if rec := e.do(t, "anna", "POST", fshort+"/action/complete", e.seenForm(t, "anna"), nil); rec.Code != http.StatusSeeOther || e.status(t) != "complete" {
		t.Fatalf("complete: code %d, status %s", rec.Code, e.status(t))
	}
}

// A complete finding's bar: Revert (to draft), Mark reported, Withdraw; a
// reported one's: Revert (to complete), Withdraw; a withdrawn one's:
// Restore. Every account gets the same bar.
func TestSimpleCompleteSlots(t *testing.T) {
	e := setupSimple(t)
	e.toCompleteSimple(t)
	revert := func(act, head string) string {
		return `<button type="button" class="btn w136 secondary" id="wf-` + act + `" aria-keyshortcuts="Shift&#43;U" data-slot="` + act + `" data-action="` + act + `" title="` + head + `" aria-controls="wf-` + act + `-reason" aria-expanded="false" data-reason-toggle>Revert</button>`
	}
	panel := func(act, head string) string {
		return `<form method="post" action="/e/acme/f/001/action/` + act + `" class="wfpanel ` + act + `" id="wf-` + act + `-reason" hidden>
    <div class="panelhead"><h2>` + head + `</h2></div>`
	}
	report := `<form method="post" action="/e/acme/f/001/action/report" class="wf-action" data-slot="report"><button class="btn w136 primary" id="wf-report" aria-keyshortcuts="Shift&#43;P" data-action="report" title="Mark reported">Mark reported</button></form>`
	withdraw := `id="wf-withdraw" aria-keyshortcuts="Shift&#43;W"`
	inOrder := func(wf string, parts ...string) bool {
		at := 0
		for _, p := range parts {
			i := strings.Index(wf[at:], p)
			if i < 0 {
				return false
			}
			at += i + len(p)
		}
		return true
	}
	for _, u := range []string{"anna", "ben"} {
		wf := wfBar(t, e.do(t, u, "GET", fshort, nil, nil).Body.String())
		if !inOrder(wf, revert("reopen", "Revert to draft"), report, withdraw, panel("reopen", "Revert to draft")) {
			t.Fatalf("%s, complete:\n%s", u, wf)
		}
	}
	if err := e.srv.Store.Transition("acme", fdir, workflow.Report, "", sAnna); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"anna", "ben"} {
		wf := wfBar(t, e.do(t, u, "GET", fshort, nil, nil).Body.String())
		if !inOrder(wf, revert("unreport", "Revert to complete"), withdraw, panel("unreport", "Revert to complete")) || strings.Contains(wf, `data-action="report"`) {
			t.Fatalf("%s, reported:\n%s", u, wf)
		}
	}
	if err := e.srv.Store.Transition("acme", fdir, workflow.Withdraw, "duplicate", sAnna); err != nil {
		t.Fatal(err)
	}
	restore := `<form method="post" action="/e/acme/f/001/action/revise" class="wf-action" data-slot="revise"><button class="btn w136 secondary" id="wf-revise" aria-keyshortcuts="Shift&#43;U" data-action="revise" title="Restore">Restore</button></form>`
	for _, u := range []string{"anna", "ben"} {
		wf := wfBar(t, e.do(t, u, "GET", fshort, nil, nil).Body.String())
		if !strings.Contains(wf, restore) || strings.Contains(wf, `data-action="withdraw"`) {
			t.Fatalf("%s, withdrawn:\n%s", u, wf)
		}
	}
}

// The simple bar has no reviewers: the author in their place, one chip,
// with no picker and no "+N", in every status; a post of the picker's form
// is refused as the store refuses it, whoever is named.
func TestSimpleNoReviewerUI(t *testing.T) {
	e := setupSimple(t)
	author := `<span class="rl">Author</span>
      <span class="chips"><span class="rev" title="anna"><span class="name">anna</span></span></span>`
	look := func(state string) {
		t.Helper()
		for _, u := range []string{"anna", "ben"} {
			wf := wfBar(t, e.do(t, u, "GET", fshort, nil, nil).Body.String())
			if !strings.Contains(wf, author) {
				t.Fatalf("%s, %s: no author chip:\n%s", u, state, wf)
			}
			for _, not := range []string{"Reviewers", `class="pop assign"`, "/reviewers", `class="btn more"`, `name="reviewer"`, "None"} {
				if strings.Contains(wf, not) {
					t.Fatalf("%s, %s: %s in the bar:\n%s", u, state, not, wf)
				}
			}
		}
	}
	look("draft")
	e.toCompleteSimple(t)
	look("complete")
}

// The reviewers endpoint refuses in the simple workflow, before any name is
// judged: the page says there are none, and nothing changes.
func TestSimpleReviewersPostRefused(t *testing.T) {
	e := setupSimple(t)
	for _, form := range []url.Values{{"reviewer": {"ben"}}, {"all": {"1"}}, {"reviewer": {"mallory"}}} {
		b := e.denied(t, "anna", fshort+"/reviewers", form)
		if !strings.Contains(b, "the simple workflow has no reviewers") {
			t.Fatalf("%v: no refusal on the page", form)
		}
		if ref, _ := e.srv.Store.Finding("acme", fdir); len(ref.F.Meta.Reviewers) != 0 {
			t.Fatalf("%v: reviewers %v", form, ref.F.Meta.Reviewers)
		}
	}
}

// The key list names Shift+A as Complete, on the finding page and for the
// ticked rows; the standard list keeps Approve.
func TestSimpleKeysOverlay(t *testing.T) {
	e := setupSimple(t)
	b := e.do(t, "anna", "GET", fshort, nil, nil).Body.String()
	for _, want := range []string{
		`<div class="krow" data-keys-for="Shift+A"><dt><kbd>Shift+A</kbd></dt><dd>Complete the ticked</dd></div>`,
		`<div class="krow" data-keys-for="Shift+A"><dt><kbd>Shift+A</kbd></dt><dd>Complete</dd></div>`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("simple key list lacks %s", want)
		}
	}
	if strings.Contains(b, "<dd>Approve") {
		t.Error("simple key list names Approve")
	}
	std := setup(t)
	b = std.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	for _, want := range []string{
		`<div class="krow" data-keys-for="Shift+A"><dt><kbd>Shift+A</kbd></dt><dd>Approve the ticked</dd></div>`,
		`<div class="krow" data-keys-for="Shift+A"><dt><kbd>Shift+A</kbd></dt><dd>Approve</dd></div>`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("standard key list lacks %s", want)
		}
	}
	if strings.Contains(b, "<dd>Complete") {
		t.Error("standard key list names Complete")
	}
}

// The top bar's account link names the account alone in the simple
// workflow (no roles); the standard one adds the role.
func TestSimpleTopBarNoRole(t *testing.T) {
	e := setupSimple(t)
	for _, p := range []string{"/", fshort, "/settings"} {
		b := e.do(t, "ben", "GET", p, nil, nil).Body.String()
		if !strings.Contains(b, `href="/settings" title="ben">ben</a>`) {
			t.Fatalf("%s: top bar:\n%s", p, b)
		}
	}
	std := setup(t)
	if b := std.do(t, "alice", "GET", "/", nil, nil).Body.String(); !strings.Contains(b, `<a class="who" href="/settings" title="alice · pentester">alice</a>`) {
		t.Fatalf("standard top bar:\n%s", b)
	}
}
