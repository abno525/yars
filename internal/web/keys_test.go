package web

import (
	"regexp"
	"strings"
	"testing"
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

// The key block left app.js for keys.js.
func TestAppJSHasNoKeyBlock(t *testing.T) {
	e := setup(t)
	if js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String(); strings.Contains(js, "function yarsEdit(") || strings.Contains(js, "function yarsSave(") {
		t.Fatal("app.js still has the key block")
	}
}
