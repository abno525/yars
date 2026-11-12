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

// D22 (a): the workflow bar keeps two rows: the steps, then reviewers and
// actions.
func TestD22TwoRowBar(t *testing.T) {
	e := setup(t)
	bar := between(e.do(t, "alice", "GET", fpath, nil, nil).Body.String(), `id="workflow"`, "</section>")
	steps, row := strings.Index(bar, `<ol class="steps">`), strings.Index(bar, `<div class="wfrow">`)
	if steps < 0 || row < steps || !strings.Contains(bar[row:], `class="wfrevs"`) {
		t.Fatalf("workflow bar is not steps, then a row with reviewers:\n%s", bar)
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
	head := titleActions(t, b)
	for _, want := range []string{`<summary class="btn secondary w136">More</summary>`, `class="btn secondary w136" href="/e/acme/f/001/history"`, `class="btn secondary w136" href="/e/acme/export"`} {
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
	// the author marks it reported or reverts it (R4); Withdraw (after her
	// last button) is left out
	alice := actionsOf(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if strings.Count(alice, "data-action=") != 2 || !strings.Contains(alice, `data-action="report"`) || !strings.Contains(alice, `data-action="reopen"`) || strings.Contains(alice, `data-slot="withdraw"`) || strings.Contains(alice, `class="slot w136"`) {
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
	// R4: reported reverts in its first slot, Withdraw still last
	if err := e.srv.Store.Transition("acme", fdir, workflow.Report, "", wDora); err != nil {
		t.Fatal(err)
	}
	check("reported", "dora", []string{"unreport", "withdraw"})
	check("reported", "alice", []string{"unreport"})
	check("reported", "bob", nil)
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
		`aria-controls="wf-return-reason"`, `id="wf-return-reason"`, `aria-controls="wf-withdraw-reason"`, `id="wf-withdraw-reason"`,
		`<textarea name="reason" required`, "Return to draft", "Withdraw finding",
	} {
		if !strings.Contains(wf, want) {
			t.Fatalf("bar lacks %s:\n%s", want, wf)
		}
	}
	if b := e.denied(t, "dora", fpath+"/action/return", url.Values{}); !strings.Contains(b, "reason is required") || e.status(t) != "verification" {
		t.Fatalf("return without reason: %s", e.status(t))
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

// titleActions is the finding page's title-row buttons.
func titleActions(t *testing.T, b string) string {
	t.Helper()
	if !strings.Contains(b, `class="actions fhead"`) || !strings.Contains(b, `id="workflow"`) {
		t.Fatalf("no title row:\n%s", b)
	}
	return between(b, `class="actions fhead"`, `id="workflow"`)
}

// D4: the title row is More, History and Export, 136 px each; More holds
// Merge into and Save as template.
func TestMoreMenuHoldsMergeAndTemplate(t *testing.T) {
	e := setup(t)
	row := titleActions(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String())
	if !strings.Contains(row, `<details class="pop more"><summary class="btn secondary w136">More</summary><div class="poplist">`) {
		t.Fatalf("no More menu:\n%s", row)
	}
	menu := between(row, `<details class="pop more">`, "</details>")
	if !strings.Contains(menu, `href="/e/acme/f/001/merge">Merge into</a>`) || !strings.Contains(menu, `href="/e/acme/f/001/template">Save as template</a>`) {
		t.Fatalf("More menu:\n%s", menu)
	}
	more, hist, exp := strings.Index(row, ">More<"), strings.Index(row, `href="/e/acme/f/001/history"`), strings.Index(row, `href="/e/acme/export"`)
	if strings.Contains(row, "w152") || !(more < hist && hist < exp) || !strings.Contains(row, `class="btn secondary w136" href="/e/acme/f/001/history"`) {
		t.Fatalf("title row:\n%s", row)
	}
	// a reviewer may save a template only: the menu holds that one link
	menu = between(titleActions(t, e.do(t, "bob", "GET", fpath, nil, nil).Body.String()), `<details class="pop more">`, "</details>")
	if strings.Contains(menu, "/merge") || !strings.Contains(menu, ">Save as template</a>") {
		t.Fatalf("bob's More menu:\n%s", menu)
	}
}

// D4: with neither right the More slot is empty, the same width.
func TestMoreSlotEmptyWithoutRights(t *testing.T) {
	e := setup(t)
	row := titleActions(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if strings.Contains(row, "pop more") || !strings.Contains(row, `<span class="slot w136"></span>`) || strings.Index(row, `<span class="slot w136"></span>`) > strings.Index(row, "/history") ||
		strings.Count(row, "w136") != 3 || strings.Contains(row, "w152") {
		t.Fatalf("alice's title row:\n%s", row)
	}
}

// D4: Possible duplicates sit in the side column, above the chat.
func TestDuplicatesInSideColumn(t *testing.T) {
	e := setup(t)
	if _, err := e.srv.Store.CreateFinding("acme", "SQL injection", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	side, dups, chat := strings.Index(b, `class="side"`), strings.Index(b, `id="dups"`), strings.Index(b, `id="chat"`)
	if side < 0 || dups < side || chat < dups || !strings.Contains(b, `<section class="panel compact dups" id="dups">`) {
		t.Fatalf("side %d, dups %d, chat %d", side, dups, chat)
	}
	// in the 560 px column the title keeps room (similarity and status go)
	// and the panel stays three rows high, so the chat below keeps its own
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	for _, want := range []string{".side .dups th:nth-child(3), .side .dups td:nth-child(3) { display: none; }", ".side .dups .dscroll { max-height: 188px; overflow-y: auto; }"} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %s", want)
		}
	}
}

// The finding page in every state renders without inline styles, with the
// title row's fixed slots.
func TestFindingPageNoInlineStyles(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	noInline(t, "draft", b)
	// a pentester gets an empty slot where More is (D4); History and Export
	// keep theirs
	if !strings.Contains(titleActions(t, b), `class="slot w136"`) || !strings.Contains(b, `class="btn secondary w136" href="/e/acme/f/001/history"`) || !strings.Contains(b, `class="btn secondary w136" href="/e/acme/export"`) {
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
