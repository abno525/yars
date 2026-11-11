package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/workflow"
)

// wfSection is the workflow bar of a finding page or fragment.
func wfSection(t *testing.T, b string) string {
	t.Helper()
	i := strings.Index(b, `id="workflow"`)
	if i < 0 {
		t.Fatalf("no workflow bar:\n%s", b)
	}
	j := strings.Index(b[i:], "</section>")
	return b[i : i+j]
}

// actionsOf is the button row of the workflow bar.
func actionsOf(t *testing.T, b string) string {
	t.Helper()
	wf := wfSection(t, b)
	i := strings.Index(wf, `class="wfstate`)
	if i < 0 {
		t.Fatalf("no wf-actions:\n%s", wf)
	}
	return wf[i:]
}

func noInline(t *testing.T, what, b string) {
	t.Helper()
	if strings.Contains(b, ` style="`) || strings.Contains(b, "<style") {
		t.Fatalf("%s has inline styles:\n%s", what, b)
	}
}

// Details and CVSS each have a Comment button, the composer can target them,
// and a comment on them is accepted and links back to the panel.
func TestCommentOnDetailsAndCVSS(t *testing.T) {
	e := setup(t)
	b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	for _, sec := range []string{"Details", "CVSS"} {
		if !strings.Contains(b, `data-comment="`+sec+`"`) {
			t.Fatalf("no Comment button for %s:\n%s", sec, b)
		}
		if !strings.Contains(b, `<option value="`+sec+`"`) {
			t.Fatalf("composer cannot target %s", sec)
		}
		if !strings.Contains(b, `id="s-`+strings.ToLower(sec)+`"`) {
			t.Fatalf("no anchor for %s", sec)
		}
		rec := e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"look"}, "section": {sec}}, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s comment: %d %s", sec, rec.Code, rec.Body.String())
		}
	}
}

// Every viewer of a status sees the same fixed slots up to the viewer's last
// button; an action before it the viewer may not take keeps its place as an
// empty slot of the same width, and the ones after it are left out, so the
// last button ends at the bar's right edge (board 3.5).
func TestWorkflowSlotsFixed(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	for u, want := range map[string]int{"alice": 4, "bob": 2, "carol": 0, "dora": 4} {
		a := actionsOf(t, e.do(t, u, "GET", fpath, nil, nil).Body.String())
		if n := strings.Count(a, "data-slot="); n != want {
			t.Fatalf("%s: %d slots in verification, want %d:\n%s", u, n, want, a)
		}
	}
	bob := actionsOf(t, e.do(t, "bob", "GET", fpath, nil, nil).Body.String())
	for _, want := range []string{`data-action="return"`, `data-action="clear"`, ">Sign off<"} {
		if !strings.Contains(bob, want) {
			t.Fatalf("bob lacks %s:\n%s", want, bob)
		}
	}
	if strings.Contains(bob, `data-slot="withdraw"`) || strings.Contains(bob, `data-slot="approve"`) {
		t.Fatalf("bob holds slots he never fills:\n%s", bob)
	}
	// a director before any sign-off: Approve shown disabled, with the reason
	dora := actionsOf(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String())
	if !strings.Contains(dora, `data-action="approve" disabled`) || !strings.Contains(dora, "Needs 1 sign-off") || !strings.Contains(dora, `data-action="withdraw"`) {
		t.Fatalf("dora before sign-off:\n%s", dora)
	}
	// after signing off, the Sign off button stays (disabled) in its place;
	// the green reviewer chip says it, so no "Signed off" text in the row
	e.do(t, "bob", "POST", fpath+"/action/clear", url.Values{}, nil)
	bob = actionsOf(t, e.do(t, "bob", "GET", fpath, nil, nil).Body.String())
	if !strings.Contains(bob, `data-action="clear" disabled`) || !strings.Contains(bob, `data-action="return"`) || strings.Contains(bob, "Signed off") {
		t.Fatalf("bob after sign-off:\n%s", bob)
	}
	// the state slot is still rendered, empty, so the buttons keep their place
	if !strings.HasPrefix(bob, `class="wfstate" id="wf-state" title=""></span>`) || strings.Count(bob, "data-slot=") != 2 {
		t.Fatalf("bob's state slot after sign-off:\n%s", bob)
	}
	if a := actionsOf(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String()); strings.Contains(a, `data-action="approve" disabled`) {
		t.Fatalf("approve still disabled:\n%s", a)
	}
}

// The finding header buttons line up with the workflow bar buttons below
// them: 136 wide, 8 apart, the bar's right inset (16 padding + 1 border).
func TestFindingHeadAlignsWithBar(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", fpath, nil, nil).Body.String()
	i := strings.Index(b, `<div class="actions fhead">`)
	if i < 0 {
		t.Fatalf("no fhead actions:\n%s", b)
	}
	head := b[i : strings.Index(b[i:], "</div>")+i]
	for _, want := range []string{`class="btn secondary w136" href="/e/acme/f/001/history"`, `class="btn secondary w136" href="/e/acme/export"`} {
		if !strings.Contains(head, want) {
			t.Fatalf("head lacks %s:\n%s", want, head)
		}
	}
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	// one inset for both, so they can't drift apart
	for _, want := range []string{".titlerow .actions.fhead { gap: 8px; padding-right: calc(var(--wf-inset) + 1px); }",
		".wfrow { height: 56px; padding: 0 var(--wf-inset);", "--wf-inset: 16px;"} {
		if !strings.Contains(css, want) {
			t.Fatalf("style.css lacks %s", want)
		}
	}
}

func TestWorkflowSlotsComplete(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	dora := actionsOf(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String())
	for _, want := range []string{`data-action="withdraw"`, `data-action="reopen"`, `data-action="report"`, ">Mark reported<", "w136"} {
		if !strings.Contains(dora, want) {
			t.Fatalf("dora on complete lacks %s:\n%s", want, dora)
		}
	}
	// the author marks it reported; Reopen keeps its empty slot, Withdraw
	// (after her last button) is left out
	alice := actionsOf(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if strings.Count(alice, "data-action=") != 1 || !strings.Contains(alice, `data-action="report"`) || strings.Count(alice, `class="slot w136"`) != 1 || strings.Contains(alice, `data-slot="withdraw"`) {
		t.Fatalf("alice on complete:\n%s", alice)
	}
	e.pen2(t)
	pen2 := actionsOf(t, e.do(t, "pen2", "GET", fpath, nil, nil).Body.String())
	if strings.Contains(pen2, "data-slot=") {
		t.Fatalf("pen2 on complete:\n%s", pen2)
	}
}

// slotOrder is the data-slot names of the bar's action row, left to right.
func slotOrder(t *testing.T, b string) []string {
	t.Helper()
	wf := wfSection(t, b)
	i := strings.Index(wf, `class="wf-actions"`)
	if i < 0 {
		t.Fatalf("no wf-actions:\n%s", wf)
	}
	var out []string
	for _, part := range strings.Split(wf[i:], `data-slot="`)[1:] {
		out = append(out, part[:strings.Index(part, `"`)])
	}
	return out
}

// Withdraw is the right-most action in every status that has it; empty
// slots sit left of it, and a viewer who can't withdraw has no slot for it.
func TestWithdrawRightMost(t *testing.T) {
	e := setup(t)
	check := func(stage, u string, want []string) {
		t.Helper()
		got := slotOrder(t, e.do(t, u, "GET", fpath, nil, nil).Body.String())
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("%s as %s: slots %v, want %v", stage, u, got, want)
		}
	}
	check("draft", "alice", []string{"submit", "withdraw"})
	check("draft", "bob", nil)
	e.toVerification(t)
	check("verification", "dora", []string{"return", "clear", "approve", "withdraw"})
	check("verification", "bob", []string{"return", "clear"})
	e = setup(t)
	e.toComplete(t)
	check("complete", "dora", []string{"reopen", "report", "withdraw"})
	check("complete", "alice", []string{"reopen", "report"})
	// the button itself is last in the row, not just its slot
	a := actionsOf(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String())
	if strings.LastIndex(a, `data-action="withdraw"`) < strings.LastIndex(a, `data-action="report"`) {
		t.Fatalf("withdraw before report:\n%s", a)
	}
}

func TestWorkflowDraftAndWithdrawn(t *testing.T) {
	e := setup(t)
	alice := actionsOf(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if !strings.Contains(alice, `data-action="submit" disabled`) || !strings.Contains(alice, `data-action="withdraw"`) || !strings.Contains(alice, "to fix") {
		t.Fatalf("alice draft:\n%s", alice)
	}
	if b := actionsOf(t, e.do(t, "bob", "GET", fpath, nil, nil).Body.String()); strings.Contains(b, "data-slot=") {
		t.Fatalf("bob draft:\n%s", b)
	}
	e.do(t, "alice", "POST", fpath+"/action/withdraw", url.Values{"reason": {"Duplicate"}}, nil)
	b := e.do(t, "dora", "GET", fpath, nil, nil).Body.String()
	a := actionsOf(t, b)
	if !strings.Contains(a, `data-action="revise"`) || !strings.Contains(a, ">Restore<") {
		t.Fatalf("dora withdrawn:\n%s", a)
	}
	wf := wfSection(t, b)
	if strings.Contains(wf, "step current") || strings.Contains(wf, "step done") {
		t.Fatalf("withdrawn finding marks steps:\n%s", wf)
	}
	if !strings.Contains(b, `class="tag status-withdrawn"`) || !strings.Contains(b, "Withdrawn by alice") || !strings.Contains(b, `class="withdrawn-title"`) {
		t.Fatalf("withdrawn page:\n%s", b)
	}
	if bob := actionsOf(t, e.do(t, "bob", "GET", fpath, nil, nil).Body.String()); strings.Contains(bob, "data-slot=") {
		t.Fatalf("bob withdrawn:\n%s", bob)
	}
}

// Return and Withdraw open a reason form under the bar; the reason is required.
func TestReasonPanels(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	b := e.do(t, "dora", "GET", fpath, nil, nil).Body.String()
	wf := wfSection(t, b)
	for _, want := range []string{
		`aria-controls="wf-return"`, `id="wf-return"`, `aria-controls="wf-withdraw"`, `id="wf-withdraw"`,
		`<textarea name="reason" required`, "Return to draft", "Withdraw finding",
	} {
		if !strings.Contains(wf, want) {
			t.Fatalf("bar lacks %s:\n%s", want, wf)
		}
	}
	if rec := e.do(t, "dora", "POST", fpath+"/action/return", url.Values{}, nil); rec.Code != http.StatusBadRequest || e.status(t) != "verification" {
		t.Fatalf("return without reason: %d", rec.Code)
	}
	e.do(t, "bob", "POST", fpath+"/action/return", url.Values{"reason": {"Add the request"}}, nil)
	b = e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	wf = wfSection(t, b)
	if !strings.Contains(wf, `class="wfbanner returned"`) || !strings.Contains(wf, "Returned by bob") || !strings.Contains(wf, "Add the request") {
		t.Fatalf("returned banner:\n%s", wf)
	}
}

// Reviewer chips: at most three, then a +N button listing everyone.
func TestReviewerChips(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.DB().AddUser(config.User{Username: "erin", Role: "reviewer", PasswordHash: pwHash}); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.Store.SetReviewers("acme", fdir, []string{"bob", "carol", "dora", "erin"}, wAlice); err != nil {
		t.Fatal(err)
	}
	wf := wfSection(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if n := strings.Count(wf, `class="rev`); n != 3 {
		t.Fatalf("%d chips:\n%s", n, wf)
	}
	if !strings.Contains(wf, `class="btn more`) || !strings.Contains(wf, ">+1<") || !strings.Contains(wf, "erin") {
		t.Fatalf("no +N list:\n%s", wf)
	}
	if !strings.Contains(wf, `title="bob"`) {
		t.Fatal("chip lacks full name on hover")
	}
}

// Resolved threads collapse to one row with Show/Hide in a fixed column.
func TestResolvedThreadToggle(t *testing.T) {
	e := setup(t)
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"Typo in step 2"}}, nil)
	id := e.chatIDs(t)[0]
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"resolves": {id}}, nil)
	b := e.do(t, "alice", "GET", fshort+"/chat", nil, nil).Body.String()
	if !strings.Contains(b, `class="rtoggle">Hide<`) || !strings.Contains(b, "Typo in step 2") {
		t.Fatalf("shown resolved thread:\n%s", b)
	}
	b = e.do(t, "alice", "POST", fpath+"/chat/"+id+"/hide", url.Values{}, nil).Body.String()
	if !strings.Contains(b, `class="rtoggle">Show<`) || strings.Contains(b, `class="msg"`) {
		t.Fatalf("hidden resolved thread:\n%s", b)
	}
	noInline(t, "chat list", b)
}

func TestEditorModes(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath+"/s/Impact/edit", nil, nil).Body.String()
	for _, want := range []string{`data-mode="write"`, `data-mode="split"`, `data-mode="preview"`, `class="editor" data-view="split"`, `data-guard`, `data-guard-cancel`} {
		if !strings.Contains(b, want) {
			t.Fatalf("editor lacks %s:\n%s", want, b)
		}
	}
	noInline(t, "editor", b)
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	for _, want := range []string{"beforeunload", "htmx:confirm", "data-mode", "defaultValue"} {
		if !strings.Contains(js, want) {
			t.Fatalf("app.js lacks %s", want)
		}
	}
	rec := e.do(t, "bob", "POST", fpath+"/s/Impact", url.Values{"body": {"bob text"}, "base": {"0000000000000000"}}, nil)
	c := rec.Body.String()
	for _, want := range []string{`class="cbar`, ">Keep mine<", ">Take theirs<", "bob text"} {
		if !strings.Contains(c, want) {
			t.Fatalf("conflict view lacks %s:\n%s", want, c)
		}
	}
	noInline(t, "conflict", c)
}

func TestCVSSBuilderLayout(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "POST", fpath+"/cvss/calc", vecForm(nil), nil).Body.String()
	for _, want := range []string{`class="mrow"`, `class="ns">Not std<`, `class="std"`, `class="scorebox"`, "1 reason missing", `aria-invalid="true"`} {
		if !strings.Contains(b, want) && !(want == "1 reason missing" && strings.Contains(b, "reasons missing")) {
			t.Fatalf("cvss editor lacks %s:\n%s", want, b)
		}
	}
	noInline(t, "cvss editor", b)
	e.do(t, "alice", "POST", fpath+"/cvss", vecForm(map[string]string{"reason_AC": "a", "reason_C": "b", "reason_I": "c"}), nil)
	p := e.do(t, "alice", "GET", fpath+"/cvss", nil, nil).Body.String()
	if !strings.Contains(p, `class="mgrid`) || !strings.Contains(p, `class="mval nsval"`) {
		t.Fatalf("cvss panel:\n%s", p)
	}
}

// The finding page in every state renders without inline styles, with the
// title row's fixed slots.
func TestFindingPageNoInlineStyles(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	noInline(t, "draft", b)
	// a pentester gets an empty slot where Save as template is; History fills
	// the slot it used to keep
	if !strings.Contains(b, `class="slot w152"`) || !strings.Contains(b, `class="btn secondary w136" href="/e/acme/f/001/history"`) || !strings.Contains(b, `class="btn secondary w136" href="/e/acme/export"`) {
		t.Fatalf("title row slots:\n%s", b)
	}
	e.toVerification(t)
	noInline(t, "verification", e.do(t, "bob", "GET", fpath, nil, nil).Body.String())
	noInline(t, "details editor", e.do(t, "alice", "GET", fpath+"/details/edit", nil, nil).Body.String())
	noInline(t, "cvss edit", e.do(t, "alice", "GET", fpath+"/cvss/edit", nil, nil).Body.String())
	if err := e.srv.Store.Transition("acme", fdir, workflow.Withdraw, "dup", wDora); err != nil {
		t.Fatal(err)
	}
	noInline(t, "withdrawn", e.do(t, "dora", "GET", fpath, nil, nil).Body.String())
}
