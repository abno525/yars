package web

import (
	"html"
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
	for _, want := range []string{`aria-keyshortcuts~="Control+S"`, `aria-keyshortcuts~="E"`, "requestSubmit", "preventDefault"} {
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
	for _, want := range []string{"data-nosave", ".conflict", "data-redact-save", "data-redact-undo", "data-kskip", "function yarsComment"} {
		if want == "function yarsComment" {
			want = "yarsComment("
		}
		if !strings.Contains(js, want) {
			t.Errorf("keys.js lacks %s", want)
		}
	}
}

var keyTagRe = regexp.MustCompile(`<button[^>]*aria-keyshortcuts="([^"]+)"[^>]*>`)

// barKeys maps each key of the workflow bar to its button's opening tag.
func barKeys(t *testing.T, b string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range keyTagRe.FindAllStringSubmatch(wfSection(t, b), -1) {
		k := html.UnescapeString(m[1]) // html/template writes + as &#43;
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
	// the panel's own buttons carry no key
	if strings.Contains(between(wf, `id="wf-withdraw-reason"`, "</form>"), "aria-keyshortcuts") {
		t.Errorf("a key in Withdraw's panel:\n%s", wf)
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

// The key block left app.js for keys.js.
func TestAppJSHasNoKeyBlock(t *testing.T) {
	e := setup(t)
	if js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String(); strings.Contains(js, "function yarsEdit(") || strings.Contains(js, "function yarsSave(") {
		t.Fatal("app.js still has the key block")
	}
}
