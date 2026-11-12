package web

import (
	"html"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"yars/internal/workflow"
)

// keyed is the tags that carry aria-keyshortcuts="<key>".
func keyed(b, key string) []string {
	return regexp.MustCompile(`<button[^>]*aria-keyshortcuts="`+regexp.QuoteMeta(key)+`"[^>]*>[^<]*`).FindAllString(b, -1)
}

// E opens a section's editor: every Edit (or Calculate) button of the
// finding page carries the shortcut, and nothing else does.
func TestEditShortcutOnEditButtons(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	got := keyed(b, "E")
	if len(got) < 4 {
		t.Fatalf("E on %d buttons:\n%s", len(got), strings.Join(got, "\n"))
	}
	for _, g := range got {
		if !strings.HasSuffix(g, ">Edit") && !strings.HasSuffix(g, ">Calculate") {
			t.Errorf("E on a button that is not Edit: %s", g)
		}
	}
	for _, id := range []string{`hx-target="#details"`, `hx-target="#assets"`, `hx-target="#cvss"`, `hx-target="#s-impact"`} {
		if !strings.Contains(strings.Join(got, "\n"), id) {
			t.Errorf("no E on the Edit button with %s", id)
		}
	}
	// the report tab's sections use the same panel
	if r := e.do(t, "alice", "GET", "/e/acme/report", nil, nil).Body.String(); len(keyed(r, "E")) == 0 {
		t.Error("report sections lack E")
	}
	// a locked finding has nothing to edit
	e.toComplete(t)
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, `aria-keyshortcuts="E"`) {
		t.Errorf("locked finding still offers E:\n%s", strings.Join(keyed(b, "E"), "\n"))
	}
}

// Ctrl+S presses the editor's real Save button: each editor has exactly one
// button with the shortcut, and it is Save (never Clear vector, Add row,
// Cancel or Keep mine).
func TestSaveShortcutOnSaveButtons(t *testing.T) {
	e := setup(t)
	// a stored vector, so the CVSS editor shows Clear vector before Save
	e.do(t, "alice", "POST", fpath+"/cvss", vecForm(map[string]string{"reason_AC": "a", "reason_C": "b", "reason_I": "c"}), nil)
	editors := map[string]string{
		"section": fpath + "/s/Impact/edit",
		"details": fpath + "/details/edit",
		"assets":  fpath + "/assets/edit",
		"cvss":    fpath + "/cvss/edit",
		"report":  "/e/acme/report/s/Scope/edit",
	}
	for name, u := range editors {
		b := e.do(t, "alice", "GET", u, nil, nil).Body.String()
		got := keyed(b, "Control+S")
		if len(got) != 1 || !strings.HasSuffix(got[0], ">Save") || !strings.Contains(got[0], `class="btn save sm w96"`) {
			t.Errorf("%s editor: Control+S on %q", name, got)
		}
		if name == "cvss" && !strings.Contains(b, ">Clear vector<") {
			t.Errorf("cvss editor without Clear vector:\n%s", b)
		}
	}
	// keys.js has the handlers
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	for _, want := range []string{"yarsHasKey(subs[i], 'Control+S')", `aria-keyshortcuts~="E"`, "btn.click()", "preventDefault"} {
		if !strings.Contains(js, want) {
			t.Errorf("keys.js lacks %s", want)
		}
	}
}

// K1–K10: one dispatcher in keys.js, loaded on every page after app.js.
func TestKeysScriptLoaded(t *testing.T) {
	e := setup(t)
	for _, u := range []string{"alice", ""} {
		p := fpath
		if u == "" {
			p = "/login"
		}
		b := e.do(t, u, "GET", p, nil, nil).Body.String()
		if !strings.Contains(b, `<script src="`+staticPrefix()+`/keys.js" defer></script>`) {
			t.Fatalf("%s: no keys.js:\n%s", p, between(b, "<head>", "</head>"))
		}
	}
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil)
	if js.Code != 200 {
		t.Fatalf("keys.js %d", js.Code)
	}
	for _, want := range []string{"function yarsFire", "function yarsKeyOf", "function yarsKeysOff", "isComposing", "evt.repeat"} {
		if !strings.Contains(js.Body.String(), want) {
			t.Errorf("keys.js lacks %s", want)
		}
	}
}

// tagOf is the opening tag of the element with id, of any kind ("" when
// missing).
func tagOf(b, id string) string {
	i := strings.Index(b, ` id="`+id+`"`)
	if i < 0 {
		return ""
	}
	start := strings.LastIndex(b[:i], "<")
	return b[start : i+strings.Index(b[i:], ">")+1]
}

// K2: every panel of the finding page can be selected; the chat is the
// side panel.
func TestPanelsCarrySelectHooks(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, nil)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	for _, id := range []string{"workflow", "details", "assets", "cvss", "s-description", "s-impact", "attachments", "checks"} {
		if tag := tagOf(b, id); !regexp.MustCompile(` data-kpanel[ >]`).MatchString(tag) {
			t.Errorf("#%s: %q", id, tag)
		}
	}
	if tag := tagOf(b, "chat"); !strings.Contains(tag, ` data-kpanel="side"`) {
		t.Errorf("#chat: %q", tag)
	}
}

// An editor swapped in keeps the hook, so the selection survives Edit.
func TestEditorKeepsSelectHook(t *testing.T) {
	e := setup(t)
	for id, u := range map[string]string{"s-impact": fpath + "/s/Impact/edit", "details": fpath + "/details/edit", "assets": fpath + "/assets/edit", "cvss": fpath + "/cvss/edit"} {
		if tag := tagOf(e.do(t, "alice", "GET", u, nil, nil).Body.String(), id); !regexp.MustCompile(` data-kpanel[ >]`).MatchString(tag) {
			t.Errorf("%s editor: %q", id, tag)
		}
	}
}

// K2, K5: keys.js selects panels and closes things on Esc; the selection is
// an outline (nothing moves).
func TestKeysSelectionMarkers(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	for _, want := range []string{"data-sel", "function yarsSelect", "function yarsEscape", `[data-kpanel]:not([data-kpanel="side"])`, "scrollIntoView({block: 'nearest'})"} {
		if !strings.Contains(js, want) {
			t.Errorf("keys.js lacks %s", want)
		}
	}
	if css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String(); !strings.Contains(css, "[data-kpanel][data-sel] { outline: 1px solid var(--ink); outline-offset: -1px; }") {
		t.Error("style.css lacks the selection outline")
	}
}

// K2 (after review): a click selects without scrolling; the mark goes back
// on a swapped panel before the settle; the selection outline gives way to
// an editor's and a linked panel's; a key-selected panel clears the sticky
// header; Esc reaches the CVSS editor's Cancel; the retest result has a hook.
func TestSelectionReviewFixes(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	for _, w := range []string{"yarsSelect(p, false)", "'htmx:afterSwap', yarsRemark", "a.closest('[data-kpanel].editing')", "if (!evt.isComposing && !evt.repeat) yarsEscape()"} {
		if !strings.Contains(js, w) {
			t.Errorf("keys.js lacks %s", w)
		}
	}
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	sel := strings.Index(css, "[data-kpanel][data-sel] {")
	for _, later := range []string{".panel:target {", ".panel.editing {"} {
		if i := strings.Index(css, later); sel < 0 || i < 0 || i < sel {
			t.Errorf("%s does not come after the selection outline (%d, %d)", later, sel, i)
		}
	}
	if !strings.Contains(css, "[data-kpanel] { scroll-margin-top: 80px; }") {
		t.Error("no scroll margin for selected panels")
	}
	cv := e.do(t, "alice", "GET", fpath+"/cvss/edit", nil, nil).Body.String()
	if c := regexp.MustCompile(`<button[^>]*>Cancel</button>`).FindString(cv); !strings.Contains(c, " data-guard-cancel") {
		t.Errorf("CVSS Cancel: %s", c)
	}
	rt, err := templateFS.ReadFile("templates/retest.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rt), `id="retest-result" data-kpanel>`) {
		t.Error("the retest result has no hook")
	}
}

// K3: each editor has exactly one Ctrl+S button, its Save.
func TestEditorSaveHasCtrlS(t *testing.T) {
	e := setup(t)
	for name, u := range map[string]string{"section": fpath + "/s/Impact/edit", "details": fpath + "/details/edit", "assets": fpath + "/assets/edit", "cvss": fpath + "/cvss/edit"} {
		if got := keyed(e.do(t, "alice", "GET", u, nil, nil).Body.String(), "Control+S"); len(got) != 1 || !strings.HasSuffix(got[0], ">Save") {
			t.Errorf("%s editor: %q", name, got)
		}
	}
}

// Review focus 5: Ctrl+S in the CVSS editor never presses Clear vector.
func TestCVSSClearHasNoCtrlS(t *testing.T) {
	e := setup(t)
	e.do(t, "alice", "POST", fpath+"/cvss", vecForm(map[string]string{"reason_AC": "a", "reason_C": "b", "reason_I": "c"}), nil)
	b := e.do(t, "alice", "GET", fpath+"/cvss/edit", nil, nil).Body.String()
	clear := regexp.MustCompile(`<button[^>]*>Clear vector</button>`).FindString(b)
	if clear == "" || strings.Contains(clear, "aria-keyshortcuts") {
		t.Fatalf("Clear vector: %q", clear)
	}
}

// K3: Ctrl+S never submits the login, setup or set-password forms.
func TestLoginSetupPasswordHaveNoSave(t *testing.T) {
	for _, f := range []string{"login.html", "setup.html", "password.html"} {
		b, err := templateFS.ReadFile("templates/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if form := regexp.MustCompile(`<form[^>]*>`).FindString(string(b)); !strings.Contains(form, " data-nosave") {
			t.Errorf("%s: %q", f, form)
		}
	}
	e := setup(t)
	if b := e.do(t, "", "GET", "/login", nil, nil).Body.String(); !strings.Contains(b, `action="/login" data-nosave`) {
		t.Fatalf("login page:\n%s", b)
	}
}

// K3: Enter presses a panel's one button besides Comment and Edit, so both
// are marked to be skipped.
func TestCommentAndEditAreSkippedByEnter(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	for _, id := range []string{"s-impact", "details", "assets", "cvss"} {
		p := between(b, `id="`+id+`"`, "</section>")
		for _, label := range []string{">Comment</button>", ">Edit</button>"} {
			if id == "cvss" && label == ">Edit</button>" {
				label = ">Calculate</button>"
			}
			btn := regexp.MustCompile(`<button[^>]*` + regexp.QuoteMeta(label)).FindString(p)
			if !strings.Contains(btn, " data-kskip") {
				t.Errorf("%s %s: %q", id, label, btn)
			}
		}
	}
}

// K3: keys.js saves the focused form (never one marked data-nosave), and in
// a conflict only moves focus to Keep mine; Ctrl+S and Ctrl+Z serve the
// Redact dialog.
func TestKeysSaveMarkers(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	for _, want := range []string{"data-nosave", ".conflict", ".cbar button", "data-redact-save", "data-redact-undo", "data-kskip", "yarsComment("} {
		if !strings.Contains(js, want) {
			t.Errorf("keys.js lacks %s", want)
		}
	}
}

var keyTagRe = regexp.MustCompile(`<button[^>]*aria-keyshortcuts="([^"]+)"[^>]*>`)

// barKeys maps each workflow key of the bar to its button's opening tag
// (the Control+ keys of its forms' buttons left out).
func barKeys(t *testing.T, b string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range keyTagRe.FindAllStringSubmatch(wfSection(t, b), -1) {
		k := html.UnescapeString(m[1]) // html/template writes + as &#43;
		if strings.HasPrefix(k, "Control+") {
			continue
		}
		if _, dup := out[k]; dup {
			t.Errorf("%s twice on the bar", k)
		}
		out[k] = m[0]
	}
	return out
}

// K4, review focus 2: a workflow key is on the rendered button only, so it
// follows the viewer's rights and the finding's state; each slot button has
// a stable id, and its reason panel another.
func TestWorkflowKeysPerRoleAndState(t *testing.T) {
	e := setup(t)
	page := func(u string) string { return e.do(t, u, "GET", fpath, nil, nil).Body.String() }
	want := func(who string, keys map[string]string, has map[string]string, not ...string) {
		t.Helper()
		for k, id := range has {
			tag, ok := keys[k]
			if !ok || !strings.Contains(tag, ` id="`+id+`"`) {
				t.Errorf("%s: %s on %q, want id %s (bar keys %v)", who, k, tag, id, keys)
			}
		}
		for _, k := range not {
			if tag, ok := keys[k]; ok {
				t.Errorf("%s: %s present: %s", who, k, tag)
			}
		}
	}
	b := page("alice")
	keys := barKeys(t, b)
	want("draft, author", keys, map[string]string{"Shift+S": "wf-submit", "Shift+W": "wf-withdraw"}, "Shift+A", "Shift+O", "Shift+R", "Shift+P", "Shift+U")
	wf := wfSection(t, b)
	for _, s := range []string{`aria-controls="wf-withdraw-reason"`, `class="wfpanel withdraw" id="wf-withdraw-reason"`, `data-reason-cancel="wf-withdraw-reason"`} {
		if !strings.Contains(wf, s) {
			t.Errorf("Withdraw's panel: no %s:\n%s", s, wf)
		}
	}
	if n := strings.Count(b, ` id="wf-withdraw"`); n != 1 {
		t.Errorf("id wf-withdraw %d times", n)
	}
	// the panel's own button carries Ctrl+Enter only
	if p := html.UnescapeString(between(wf, `id="wf-withdraw-reason"`, "</form>")); strings.Contains(p, "Shift+") || !strings.Contains(p, `aria-keyshortcuts="Control+Enter">Withdraw</button>`) {
		t.Errorf("Withdraw's panel:\n%s", p)
	}

	e.toVerification(t)
	want("verification, reviewer", barKeys(t, page("bob")), map[string]string{"Shift+O": "wf-clear", "Shift+R": "wf-return"}, "Shift+A", "Shift+S", "Shift+W")
	// before a sign-off dora's Approve is there but disabled, so its key does nothing
	if tag := barKeys(t, page("dora"))["Shift+A"]; !strings.Contains(tag, " disabled") {
		t.Errorf("dora before a sign-off: Approve %q", tag)
	}
	if err := e.srv.Store.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	keys = barKeys(t, page("dora"))
	want("verification, director after a sign-off", keys, map[string]string{"Shift+A": "wf-approve"})
	if strings.Contains(keys["Shift+A"], " disabled") {
		t.Errorf("Approve disabled after a sign-off: %s", keys["Shift+A"])
	}
	want("verification, author", barKeys(t, page("alice")), nil, "Shift+A", "Shift+O")

	if err := e.srv.Store.Transition("acme", fdir, workflow.Approve, "", wDora); err != nil {
		t.Fatal(err)
	}
	want("complete, director", barKeys(t, page("dora")), map[string]string{"Shift+U": "wf-reopen", "Shift+P": "wf-report", "Shift+W": "wf-withdraw"}, "Shift+A", "Shift+S")
	want("complete, reviewer", barKeys(t, page("bob")), nil, "Shift+U", "Shift+P", "Shift+W")

	if err := e.srv.Store.Archive("acme", wDora); err != nil {
		t.Fatal(err)
	}
	if wf := wfSection(t, page("dora")); strings.Contains(wf, "aria-keyshortcuts") {
		t.Errorf("archived: keys on the bar:\n%s", wf)
	}

	// Check (rules on) has Shift+C
	e = setup(t)
	e.rules(t, "- id: no-zebra\n  target: title\n  regex_forbid: 'zebra'\n", nil)
	want("draft with rules, author", barKeys(t, page("alice")), map[string]string{"Shift+C": "wf-check"})
}

// K4: Submit, Approve and Mark reported in the bulk menu carry the bar's
// keys; nothing else there does.
func TestBulkKeys(t *testing.T) {
	e := setup(t)
	bar := html.UnescapeString(toolbarOf(e.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String()))
	items := regexp.MustCompile(`<button [^>]*role="menuitem"[^>]*>`).FindAllString(bar, -1)
	if len(items) == 0 {
		t.Fatalf("no menu:\n%s", bar)
	}
	wantKey := map[string]string{"submit": "Shift+S", "approve": "Shift+A", "report": "Shift+P"}
	for _, it := range items {
		act := actRe.FindStringSubmatch(it)[1]
		k := wantKey[act]
		got := ""
		if m := regexp.MustCompile(`aria-keyshortcuts="([^"]+)"`).FindStringSubmatch(it); m != nil {
			got = m[1]
		}
		if got != k {
			t.Errorf("%s: key %q, want %q: %s", act, got, k, it)
		}
	}
	// the director's inbox bar too
	in := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	if bar := html.UnescapeString(toolbarOf(in)); bar == "" || !strings.Contains(bar, `data-act="approve" aria-keyshortcuts="Shift+A"`) {
		t.Errorf("inbox bar lacks Shift+A:\n%s", bar)
	}
	// keys.js presses a bulk entry only with a ticked row, and the bar wins
	js := e.do(t, "dora", "GET", "/static/keys.js", nil, nil).Body.String()
	for _, w := range []string{"function yarsBulkFire", "input[name=id]:checked", "getElementById('workflow')"} {
		if !strings.Contains(js, w) {
			t.Errorf("keys.js lacks %s", w)
		}
	}
}

// K6: the navigation keys are on the links they follow: Inbox I, Findings F
// (inside an engagement), New finding N, the Team board tab B, History
// Shift+H.
func TestNavKeysDeclared(t *testing.T) {
	e := setup(t)
	eng := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	nav := between(eng, `<nav class="nav">`, "</nav>")
	for _, w := range []string{`href="/inbox" aria-keyshortcuts="I"`, `href="/e/acme" aria-keyshortcuts="F"`} {
		if !strings.Contains(nav, w) {
			t.Errorf("nav lacks %s:\n%s", w, nav)
		}
	}
	// outside an engagement f goes to the engagement last opened, else to the list
	if home := between(e.do(t, "alice", "GET", "/", nil, nil).Body.String(), `<nav class="nav">`, "</nav>"); !strings.Contains(home, `href="/" aria-keyshortcuts="F"`) {
		t.Errorf("no F outside an engagement:\n%s", home)
	}
	if !regexp.MustCompile(`href="/e/acme/findings/new" aria-keyshortcuts="N">New finding<`).MatchString(eng) {
		t.Error("New finding lacks N")
	}
	if !strings.Contains(eng, `<a aria-keyshortcuts="T B" class="etab" href="/e/acme/board">`) {
		t.Errorf("the board tab lacks T and B:\n%s", between(eng, `<nav class="etabs"`, "</nav>"))
	}
	if n := strings.Count(eng, `aria-keyshortcuts="T B"`) + strings.Count(eng, `aria-keyshortcuts="N"`); n != 2 {
		t.Errorf("T B and N on %d links", n)
	}
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, `href="/e/acme/f/001/history" aria-keyshortcuts="Shift+H">History<`) {
		t.Error("the finding's History lacks Shift+H")
	}
	tpl, err := templateFS.ReadFile("templates/template.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tpl), `/history" aria-keyshortcuts="Shift+H">History<`) {
		t.Error("the template's History lacks Shift+H")
	}
}

// An engagement's pages: t (or b) Team board, o Overview, r Report, s
// Settings, e Export; on a page with panels e stays Edit. The ? list has
// them in an Engagement group, shown where the tabs are.
func TestEngagementTabKeys(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/e/acme", "/e/acme/overview", "/e/acme/report", "/e/acme/settings", "/e/acme/board"} {
		b := e.do(t, "alice", "GET", p, nil, nil).Body.String()
		tabs := between(b, `<nav class="etabs"`, "</nav>")
		for _, w := range []string{`<a aria-keyshortcuts="T B" class="etab`, `<a aria-keyshortcuts="O" class="etab`, `<a aria-keyshortcuts="R" class="etab`, `<a aria-keyshortcuts="S" class="etab`} {
			if !strings.Contains(tabs, w) {
				t.Errorf("%s: tabs lack %s:\n%s", p, w, tabs)
			}
		}
		if !strings.Contains(b, `<a class="btn secondary w128" href="/e/acme/export" aria-keyshortcuts="E">Export</a>`) {
			t.Errorf("%s: Export lacks E", p)
		}
		d := between(b, `data-keys-group="eng"`, "</section>")
		for _, w := range []string{`<dt><kbd>t</kbd><kbd>b</kbd></dt><dd>Team board</dd>`, `<dt><kbd>o</kbd></dt><dd>Overview</dd>`, `<dt><kbd>r</kbd></dt><dd>Report</dd>`,
			`<dt><kbd>s</kbd></dt><dd>Settings</dd>`, `data-keys-if="html:not(:has([data-kpanel]))"><dt><kbd>e</kbd></dt><dd>Export</dd>`} {
			if !strings.Contains(d, w) {
				t.Errorf("%s: the Engagement group lacks %s:\n%s", p, w, d)
			}
		}
	}
	// the finding page has no tabs: none of these keys there
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); strings.Contains(b, `aria-keyshortcuts="O"`) || strings.Contains(b, `aria-keyshortcuts="T B"`) {
		t.Error("tab keys on the finding page")
	}
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	for _, w := range []string{"if (key === 'E') { if (yarsEdit() || (!document.querySelector('[data-kpanel]') && yarsFire('E'))) evt.preventDefault(); return; }",
		`show('[data-keys-group="eng"]', document.querySelector('.etabs'));`} {
		if !strings.Contains(js, w) {
			t.Errorf("keys.js lacks %s", w)
		}
	}
}

// The findings list and the engagements list: the digits pick the state
// filter by its place (1 All, 2 Draft, 3 Verification; 1 All, 2 Active,
// 3 Archived), and ↓ ↑ move the row focus as j k do, so the page does not
// scroll instead; the ? list names both.
func TestListFilterDigitsAndArrows(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	for id, key := range map[string]string{"flt-all": "1", "flt-draft": "2", "flt-verification": "3", "flt-withdrawn": "7"} {
		if tag := tagOf(b, id); !strings.Contains(tag, ` aria-keyshortcuts="`+key+`"`) {
			t.Errorf("#%s lacks %s: %s", id, key, tag)
		}
	}
	home := between(e.do(t, "alice", "GET", "/", nil, nil).Body.String(), `aria-label="Show"`, "</nav>")
	for _, w := range []string{`aria-keyshortcuts="1" href="/engagements">All`, `aria-keyshortcuts="2" href="/engagements?show=active">Active`, `aria-keyshortcuts="3" href="/engagements?show=archived">Archived`} {
		if !strings.Contains(home, w) {
			t.Errorf("engagements filter lacks %s:\n%s", w, home)
		}
	}
	// the arrows are the two lists' only (data-arrows), not History's or
	// Export's; held down they go on stepping; never in an open menu
	if !strings.Contains(b, `<table class="table findings" data-arrows>`) {
		t.Error("the findings table lacks data-arrows")
	}
	if !strings.Contains(e.do(t, "alice", "GET", "/", nil, nil).Body.String(), `<table class="table englist" data-arrows>`) {
		t.Error("the engagements table lacks data-arrows")
	}
	for _, f := range []string{"history.html", "export.html", "inbox.html", "notifications.html"} {
		if src, _ := templateFS.ReadFile("templates/" + f); strings.Contains(string(src), "data-arrows") {
			t.Errorf("%s takes the arrows", f)
		}
	}
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	fn := js[strings.Index(js, "function yarsArrowKey(evt, key)"):]
	fn = fn[:strings.Index(fn, "\n}\n")]
	for _, w := range []string{"document.querySelector('[data-arrows]')", "t.closest('.bmenu, [role=menu]')", "yarsRowStep(key === 'ArrowDown' ? 1 : -1)", "evt.preventDefault();"} {
		if !strings.Contains(fn, w) {
			t.Errorf("yarsArrowKey lacks %s:\n%s", w, fn)
		}
	}
	if strings.Contains(fn, "evt.repeat") {
		t.Error("a held arrow does not step")
	}
	if a, r := strings.Index(js, "if (yarsArrowKey(evt, key)) return;"), strings.Index(js, "evt.isComposing || evt.repeat || evt.altKey"); a < 0 || a > r {
		t.Error("the arrows are not handled before the repeat check")
	}
	// the row the keys moved to is tinted whole; its title is not boxed
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	for _, w := range []string{".table tbody tr:has([data-nav]:focus-visible) > td { background: var(--mark-bg); }", ".table [data-nav]:focus-visible { outline: none; }"} {
		if !strings.Contains(css, w) {
			t.Errorf("style.css lacks %s", w)
		}
	}
	if strings.Index(css, ".table tbody tr:has([data-nav]:focus-visible)") < strings.Index(css, ".table.findings tbody tr.sel td") {
		t.Error("a ticked row's tint wins over the focused row's")
	}
	page := e.do(t, "alice", "GET", "/", nil, nil).Body.String()
	if d := between(page, `data-keys-group="lists"`, "</section>"); !strings.Contains(d, `<dt><kbd>j</kbd><kbd>k</kbd><kbd>↓</kbd><kbd>↑</kbd></dt><dd>Next or previous row</dd>`) {
		t.Errorf("the Lists group lacks the arrows:\n%s", d)
	}
	// the digits work on an empty list too, so their row is not in Lists
	// (hidden without rows)
	if d := between(page, `<h3 class="gh">Global</h3>`, "</section>"); !strings.Contains(d, `<div class="krow" data-keys-for="1"><dt><kbd>1</kbd>–<kbd>9</kbd></dt><dd>State filter</dd></div>`) {
		t.Errorf("the Global group lacks the digits:\n%s", d)
	}
}

// K7: each list row has one data-nav control, the one j/k focus.
func TestRowsCarryNav(t *testing.T) {
	e := setup(t)
	e.second(t, "bob")
	b := e.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String()
	rows, navs := strings.Count(b, "<tr data-fid="), strings.Count(b, " data-nav")
	if rows < 2 || navs != rows {
		t.Errorf("findings list: %d rows, %d data-nav", rows, navs)
	}
	if !regexp.MustCompile(`<td class="title"><a href="[^"]+" title="[^"]*" data-nav[ >]`).MatchString(b) {
		t.Error("data-nav is not on the title link")
	}
	e.toVerification(t)
	in := e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String()
	if rows, navs := strings.Count(in, `<td class="title"><a `), strings.Count(in, " data-nav"); rows == 0 || navs != rows {
		t.Errorf("inbox: %d rows, %d data-nav", rows, navs)
	}
	for _, f := range []string{"engagements.html", "templates.html", "notifications.html", "history.html", "export.html"} {
		src, err := templateFS.ReadFile("templates/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(string(src), " data-nav"); n != 1 {
			t.Errorf("%s: data-nav %d times", f, n)
		}
	}
}

// K7: htmx puts focus back on a control with the same id after a swap, so
// the filters, sort links, chat controls, retest radios and CVSS paste and
// severity have stable ids.
func TestStableIDsForFocus(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	for _, id := range []string{"flt-all", "flt-draft", "flt-withdrawn", "sort-id", "sort-title"} {
		if tag := tagOf(b, id); !strings.HasPrefix(tag, "<a ") {
			t.Errorf("#%s: %q", id, tag)
		}
	}
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"Typo in step 2"}}, nil)
	id := e.chatIDs(t)[0]
	p := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if tag := tagOf(p, "reply-"+id); !strings.Contains(tag, `name="text"`) {
		t.Errorf("reply input: %q", tag)
	}
	if tag := tagOf(p, "resolve-"+id); !strings.HasPrefix(tag, "<button") {
		t.Errorf("Resolve: %q", tag)
	}
	if tag := tagOf(p, "cvss-sev"); !strings.HasPrefix(tag, `<select name="severity"`) {
		t.Errorf("severity: %q", tag)
	}
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"resolves": {id}}, nil)
	if tag := tagOf(e.do(t, "alice", "GET", fpath, nil, nil).Body.String(), "reopen-"+id); !strings.HasPrefix(tag, "<button") {
		t.Errorf("Reopen: %q", tag)
	}
	if tag := tagOf(e.do(t, "alice", "GET", fpath+"/cvss/edit", nil, nil).Body.String(), "cvss-paste"); !strings.Contains(tag, `name="paste"`) {
		t.Errorf("paste: %q", tag)
	}
	rt, err := templateFS.ReadFile("templates/retest.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rt), `name="result" value="{{.Code}}"{{if .Checked}} checked{{end}} id="retest-{{.Code}}">`) {
		t.Error("retest radios lack their ids")
	}
}

// K7: lists: j/k move the row focus, x ticks, Shift+click and Shift+Space
// tick a range, / finds the search box, Load more focuses the first new row.
func TestRangeSelectMarkers(t *testing.T) {
	e := setup(t)
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	bulk := app[strings.Index(app, "function yarsBulkSync"):]
	for _, w := range []string{"shiftKey", "function yarsRange"} {
		if !strings.Contains(bulk, w) {
			t.Errorf("app.js's bulk block lacks %s", w)
		}
	}
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	for _, w := range []string{"[data-nav]", "'Shift+Space'", "input[type=search]", "yarsGotoOpen()", "tr.more"} {
		if !strings.Contains(js, w) {
			t.Errorf("keys.js lacks %s", w)
		}
	}
}

var htmlTagRe = regexp.MustCompile(`<html[^>]*>`)

// K9: Preferences › Keyboard shortcuts Off is stored and puts data-keys="off"
// on <html>, which keys.js reads; a bad value is refused, a form without the
// field leaves it as it is.
func TestPrefsKeysOffSaves(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "alice", "POST", "/settings/prefs", url.Values{"theme": {"system"}, "keys": {"off"}}, nil); rec.Code != 303 {
		t.Fatalf("save %d %s", rec.Code, rec.Body.String())
	}
	if u, _, _ := e.srv.Store.DB().User("alice"); !u.KeysOff {
		t.Fatal("not stored")
	}
	b := e.do(t, "alice", "GET", "/settings", nil, nil).Body.String()
	if tag := htmlTagRe.FindString(b); !strings.Contains(tag, ` data-keys="off"`) {
		t.Errorf("<html>: %s", tag)
	}
	if !strings.Contains(b, `name="keys" value="off" checked`) || strings.Contains(b, `name="keys" value="on" checked`) {
		t.Errorf("Preferences:\n%s", between(b, `id="prefs"`, "</form>"))
	}
	if rec := e.do(t, "alice", "POST", "/settings/prefs", url.Values{"theme": {"dark"}, "keys": {"maybe"}}, nil); rec.Code != 400 {
		t.Errorf("keys=maybe: %d", rec.Code)
	}
	if u, _, _ := e.srv.Store.DB().User("alice"); !u.KeysOff || u.Theme != "" {
		t.Errorf("a refused save changed something: keys off %v, theme %q", u.KeysOff, u.Theme)
	}
	e.do(t, "alice", "POST", "/settings/prefs", url.Values{"theme": {"dark"}}, nil)
	if u, _, _ := e.srv.Store.DB().User("alice"); !u.KeysOff || u.Theme != "dark" {
		t.Errorf("theme only: keys off %v, theme %q", u.KeysOff, u.Theme)
	}
	e.do(t, "alice", "POST", "/settings/prefs", url.Values{"theme": {"dark"}, "keys": {"on"}}, nil)
	if tag := htmlTagRe.FindString(e.do(t, "alice", "GET", "/", nil, nil).Body.String()); strings.Contains(tag, "data-keys") {
		t.Errorf("on again: %s", tag)
	}
	// and a form without theme leaves the theme, as one without keys leaves those
	e.do(t, "alice", "POST", "/settings/prefs", url.Values{"keys": {"off"}}, nil)
	if u, _, _ := e.srv.Store.DB().User("alice"); !u.KeysOff || u.Theme != "dark" {
		t.Errorf("keys only: keys off %v, theme %q", u.KeysOff, u.Theme)
	}
}

// K9: shortcuts are on for a new account.
func TestKeysOnByDefault(t *testing.T) {
	e := setup(t)
	b := e.do(t, "bob", "GET", "/settings", nil, nil).Body.String()
	if tag := htmlTagRe.FindString(b); strings.Contains(tag, "data-keys") {
		t.Errorf("<html>: %s", tag)
	}
	p := between(b, `id="prefs"`, "</form>")
	for _, w := range []string{`<span class="flabel">Keyboard shortcuts</span>`, `name="keys" value="on" checked`, `name="keys" value="off">`, ">On<", ">Off<"} {
		if !strings.Contains(p, w) {
			t.Errorf("Preferences lacks %s:\n%s", w, p)
		}
	}
	if n := strings.Count(p, "<button"); n != 1 {
		t.Errorf("%d buttons in Preferences, want its one Save", n)
	}
}

// K8: the shortcut list is there for a signed-in account only.
func TestOverlayOnlyWhenSignedIn(t *testing.T) {
	e := setup(t)
	if tag := tagOf(e.do(t, "alice", "GET", "/", nil, nil).Body.String(), "keys"); !strings.HasPrefix(tag, `<dialog `) || !strings.Contains(tag, ` class="gotodlg keysdlg"`) {
		t.Errorf("signed in: %q", tag)
	}
	if b := e.do(t, "", "GET", "/login", nil, nil).Body.String(); strings.Contains(b, `id="keys"`) {
		t.Error("the login page has the list")
	}
}

// K8: the list names every key of the key map, in four groups; ? opens it.
func TestOverlayListsEveryKey(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/", nil, nil).Body.String()
	d := between(b, `id="keys"`, "</dialog>")
	for _, k := range []string{"?", "/", "Ctrl+K", "Esc", "Ctrl+S", "Ctrl+Enter", "Ctrl+Z", "i", "f", "b", "n",
		"j", "k", "↓", "↑", "l", "h", "→", "←", "e", "Enter", "c", "x", "Shift+Space",
		"Shift+S", "Shift+O", "Shift+A", "Shift+P", "Shift+R", "Shift+W", "Shift+U", "Shift+C", "Shift+H"} {
		if !strings.Contains(d, "<kbd>"+k+"</kbd>") {
			t.Errorf("the list lacks %s", k)
		}
	}
	// no bar slot has Take back, so the list does not offer its key
	if strings.Contains(d, "Shift+T") {
		t.Error("the list offers Shift+T")
	}
	for _, g := range []string{">Global<", ">Finding page<", ">Lists<", ">Chat<", `data-keys-group="finding"`} {
		if !strings.Contains(d, g) {
			t.Errorf("the list lacks %s", g)
		}
	}
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	for _, w := range []string{"key === '?'", "showModal()", `[data-keys-group="finding"]`} {
		if !strings.Contains(js, w) {
			t.Errorf("keys.js lacks %s", w)
		}
	}
}

// K3 (after review): Ctrl+S needs a focused field, picks among the form's
// own submit buttons (the Control+S one, else the only one unless it is a
// Control+Enter send button) and clicks it, so a confirm still asks; a
// cancelled editor gives focus back to its panel.
func TestSaveReviewFixes(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	i := strings.Index(js, "function yarsSave()")
	if i < 0 {
		t.Fatal("no yarsSave")
	}
	save := js[i:]
	save = save[:strings.Index(save, "\n}\n")]
	for _, w := range []string{"if (!yarsTyping(a)) return;", "yarsSaveButton(form)", "btn.click()"} {
		if !strings.Contains(save, w) {
			t.Errorf("yarsSave lacks %s", w)
		}
	}
	if strings.Contains(save, "requestSubmit") || strings.Contains(save, "querySelector('button:not([type=button])')") {
		t.Errorf("yarsSave still submits without the click or takes the first descendant button:\n%s", save)
	}
	for _, w := range []string{"function yarsSaveButton(form)", "form.elements", "yarsHasKey(subs[0], 'Control+Enter')", "el.matches('[data-guard-cancel]')"} {
		if !strings.Contains(js, w) {
			t.Errorf("keys.js lacks %s", w)
		}
	}
}

// K7 (after review): Enter on a list's checkbox never submits its form (the
// browser would press the first bulk entry); with shortcuts on it opens the
// row. j/k skip disabled rows, x ticks only in a declared list, and Load
// more takes focus only from its own button.
func TestListReviewFixes(t *testing.T) {
	e := setup(t)
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	if !strings.Contains(app, `evt.target.matches('.fbulkform input[type=checkbox], input[type=checkbox][data-nav]`) {
		t.Error("app.js does not stop Enter on a list checkbox")
	}
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	rows := js[strings.Index(js, "function yarsRows()"):]
	if rows = rows[:strings.Index(rows, "\n}\n")]; !strings.Contains(rows, "!el.disabled") {
		t.Errorf("yarsRows keeps disabled rows:\n%s", rows)
	}
	for _, w := range []string{"key === 'Enter' && yarsPick(evt.target)", "if (!yarsRowOf(a)) return null;",
		"evt.detail.shouldSwap && t.contains(document.activeElement)", "a && a !== document.body) return;", "if (yarsKeysOff()) return;", `[data-keys-group="chat"]`} {
		if !strings.Contains(js, w) {
			t.Errorf("keys.js lacks %s", w)
		}
	}
	// the Chat group hides where there is no chat
	if d := between(e.do(t, "alice", "GET", "/", nil, nil).Body.String(), `id="keys"`, "</dialog>"); !strings.Contains(d, `<section class="kgroup" data-keys-group="chat">`) {
		t.Error("the Chat group is not marked")
	}
}

// M29 branch review: a key that selects a panel takes focus off a control
// left in another panel (Enter and Space then act on the selection); Enter
// on a reviewer picker checkbox never presses Assign all; list rows keep
// their focus through a live refresh (stable ids, unique per page).
func TestBranchReviewFixes(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	sel := js[strings.Index(js, "function yarsSelect("):]
	if sel = sel[:strings.Index(sel, "\n}\n")]; !strings.Contains(sel, "a.blur()") || !strings.Contains(sel, "!el.contains(a)") {
		t.Errorf("yarsSelect leaves focus behind:\n%s", sel)
	}
	// the focus after a key's edit, save or cancel rides on that request
	for _, w := range []string{"evt.detail.xhr.yarsFocus = yarsFocusAfter", "var want = xhr && xhr.yarsFocus;", "el.id === yarsFocusAfter) return;"} {
		if !strings.Contains(js, w) {
			t.Errorf("keys.js lacks %s", w)
		}
	}
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	if !strings.Contains(app, ".picker input[type=checkbox]") {
		t.Error("app.js does not stop Enter in the reviewer picker")
	}
	// plain Enter only: Ctrl+Enter there presses the picker's Save (keys.js)
	if !strings.Contains(app, "evt.key === 'Enter' && !evt.ctrlKey && !evt.metaKey && evt.target.matches") {
		t.Error("app.js stops Ctrl+Enter on list and picker checkboxes too")
	}
	// rows that need something on the page besides a key
	d := between(e.do(t, "alice", "GET", "/", nil, nil).Body.String(), `id="keys"`, "</dialog>")
	for _, w := range []string{`data-keys-if="#chat"`, `data-keys-if="#redact"`, `data-keys-if="tr input[type=checkbox]"`, `data-keys-if="input[type=checkbox][name=id]"`} {
		if !strings.Contains(d, w) {
			t.Errorf("the list lacks %s", w)
		}
	}
	if !strings.Contains(js, "[data-keys-if]") {
		t.Error("keys.js does not hide the rows a page cannot use")
	}
	e.second(t, "bob")
	b := e.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String()
	for _, row := range regexp.MustCompile(`<tr data-fid="([^"]+)"`).FindAllStringSubmatch(b, -1) {
		dir := row[1]
		if tag := tagOf(b, "row-"+dir); !strings.Contains(tag, " data-nav") {
			t.Errorf("row %s: link %q", dir, tag)
		}
		if tag := tagOf(b, "pick-"+dir); !strings.Contains(tag, `name="id"`) {
			t.Errorf("row %s: checkbox %q", dir, tag)
		}
	}
	e.toVerification(t)
	for _, u := range []string{"alice", "bob", "dora"} {
		in := e.do(t, u, "GET", "/inbox", nil, nil).Body.String()
		ids := regexp.MustCompile(` id="([^"]+)"`).FindAllStringSubmatch(in, -1)
		seen := map[string]bool{}
		for _, m := range ids {
			if seen[m[1]] {
				t.Errorf("%s inbox: id %s twice", u, m[1])
			}
			seen[m[1]] = true
		}
		if navs := strings.Count(in, " data-nav"); navs != len(regexp.MustCompile(`<a [^>]* data-nav id="row-[^"]+"`).FindAllString(in, -1)) {
			t.Errorf("%s inbox: %d rows, not every one with its id", u, navs)
		}
		if u == "bob" && !strings.Contains(in, " data-nav") {
			t.Error("bob's inbox has no rows to check")
		}
	}
}

// M29 branch review nits: a held Esc closes one thing; app.js's Esc waits
// during composition; Esc blurs a field outside the editors before it cancels
// one, and a closed reason or dismiss form gives focus back to its toggle;
// the ? list hides rows whose key the page has not got, and the Lists group
// without rows; the unused panel memory is gone.
func TestBranchReviewNits(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	for _, w := range []string{"if (!evt.isComposing && !evt.repeat) yarsEscape()", "[data-keys-for]", `[data-keys-group="lists"]`, "a field outside every editor"} {
		if !strings.Contains(js, w) {
			t.Errorf("keys.js lacks %s", w)
		}
	}
	for _, gone := range []string{"yarsLastPanel", "function yarsRemember"} {
		if strings.Contains(js, gone) {
			t.Errorf("keys.js still has %s", gone)
		}
	}
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	for _, w := range []string{"evt.key !== 'Escape' || evt.isComposing", "yarsFocusToggle("} {
		if !strings.Contains(app, w) {
			t.Errorf("app.js lacks %s", w)
		}
	}
	d := between(e.do(t, "alice", "GET", "/", nil, nil).Body.String(), `id="keys"`, "</dialog>")
	// o, r, s and e are the Engagement group's, shown where the tabs are; t b
	// only where there is a board (it needs the database); e edits only
	// where a panel has an Edit (the head's Export carries E too)
	for _, w := range []string{`<div class="krow" data-keys-for="T"><dt><kbd>t</kbd><kbd>b</kbd></dt><dd>Team board</dd></div>`,
		`<div class="krow" data-keys-if="[data-kpanel] [aria-keyshortcuts~=E]"><dt><kbd>e</kbd></dt><dd>Edit the panel</dd></div>`} {
		if !strings.Contains(d, w) {
			t.Errorf("the list lacks %s", w)
		}
	}
	for _, k := range []string{"I", "F", "N", "Shift+S", "Shift+O", "Shift+A", "Shift+P", "Shift+R", "Shift+W", "Shift+U", "Shift+C", "Shift+H"} {
		if !strings.Contains(d, `data-keys-for="`+k+`"`) {
			t.Errorf("the list's %s row is not tied to its key", k)
		}
	}
	if !strings.Contains(d, `<section class="kgroup" data-keys-group="lists">`) {
		t.Error("the Lists group is not marked")
	}
	src, err := os.ReadFile("settings.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "if err := r.ParseForm(); err != nil {") {
		t.Error("settingsPrefs reads r.Form without parsing it first")
	}
}

// The key block left app.js for keys.js.
func TestAppJSHasNoKeyBlock(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	for _, f := range []string{"function yarsEdit(", "function yarsSave(", "function yarsTyping(", "function yarsPanelOf(", "function yarsFirstField(", "var yarsLastPanel", "var yarsFocusAfter"} {
		if strings.Contains(js, f) {
			t.Errorf("app.js still has %s", f)
		}
	}
}

// K1 (after review): Ctrl+Enter presses the button of the key map's small
// forms (chat, reply, the reason forms, the reviewer picker), which carries
// Control+Enter; no editor and no other form has one, so it never posts a
// form some other way (a conflict editor, Clear vector, a confirm button).
func TestCtrlEnterButtons(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"Typo in step 2"}}, nil)
	got := func(b string) []string {
		var out []string
		for _, m := range regexp.MustCompile(`<button[^>]*aria-keyshortcuts="[^"]*Control\+Enter[^"]*"[^>]*>([^<]*)`).FindAllStringSubmatch(html.UnescapeString(b), -1) {
			out = append(out, strings.TrimSpace(m[1]))
		}
		return out
	}
	b := e.do(t, "dora", "GET", fpath, nil, nil).Body.String()
	want := map[string]bool{"Send": false, "Reply": false, "Return": false, "Withdraw": false, "Save": false}
	for _, g := range got(b) {
		if _, ok := want[g]; !ok {
			t.Errorf("Control+Enter on %q", g)
		}
		want[g] = true
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("no Control+Enter on %s", k)
		}
	}
	// the picker's Save is its Ctrl+S button too, never Assign all
	if pick := between(b, `class="picker"`, "</form>"); !strings.Contains(pick, `<button class="btn save sm w96" aria-keyshortcuts="Control+S Control+Enter">Save</button>`) {
		t.Errorf("picker:\n%s", pick)
	}
	for name, u := range map[string]string{"section": fpath + "/s/Impact/edit", "details": fpath + "/details/edit", "assets": fpath + "/assets/edit", "cvss": fpath + "/cvss/edit"} {
		if g := got(e.do(t, "alice", "GET", u, nil, nil).Body.String()); len(g) != 0 {
			t.Errorf("%s editor: Control+Enter on %v", name, g)
		}
	}
	if g := got(toolbarOf(e.do(t, "bob", "GET", "/e/acme", nil, nil).Body.String())); len(g) != 1 || g[0] != "Return" {
		t.Errorf("bulk bar: %v", g)
	}
	// the Checks strip's and the team board's Dismiss reason forms
	for f, w := range map[string]string{"checks.html": `<button class="btn save sm w120" aria-keyshortcuts="Control+Enter">{{if eq .Level "error"}}`,
		"team_board.html": `<button class="btn danger sm w112" aria-keyshortcuts="Control+Enter">Dismiss</button>`} {
		src, err := templateFS.ReadFile("templates/" + f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), w) || strings.Count(string(src), "Control+Enter") != 1 {
			t.Errorf("%s: Dismiss lacks Control+Enter, or another button has it", f)
		}
	}
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	i := strings.Index(js, "key === 'Control+Enter'")
	if i < 0 {
		t.Fatal("keys.js: no Control+Enter branch")
	}
	branch := js[i:]
	branch = branch[:strings.Index(branch, "return;\n  }")]
	for _, w := range []string{"evt.defaultPrevented", "evt.isComposing", "evt.repeat", "'Control+Enter'", ".click()"} {
		if !strings.Contains(branch, w) {
			t.Errorf("the Control+Enter branch lacks %s:\n%s", w, branch)
		}
	}
	if strings.Contains(branch, "requestSubmit()") {
		t.Error("the Control+Enter branch submits a form without its button")
	}
}
