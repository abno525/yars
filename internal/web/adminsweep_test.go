package web

import (
	"slices"
	"strings"
	"testing"
)

// Graphite keeps no navy from the light theme. The light theme's navy
// (#13233F, #1E3A66, #2E4A78) was the old Navy dark theme's too, so the
// tokens that carry it and had no dark value (--navy, --navy-600,
// --head-field-line) kept it when Graphite replaced the dark values
// (5298530 changed the dark tokens only): the top bar's select, Go to and
// Log out had navy borders, the Pentest, Complete, AI and role tags, the
// done workflow steps, toasts and toggles navy fills on near-black. Every
// light token that holds one of them has a dark value, none of them a navy:
// --navy is Graphite's Complete (--bar-complete, which the light theme also
// gives the navy; the confirmed lead's tag already wears it under white
// text), --head-field-line Graphite's field border (--field-line), and
// --navy-600 the step between that Complete and Verification, as in light.
func TestGraphiteHasNoNavy(t *testing.T) {
	css, _ := scan(stylesheet(t))
	r, err := tokenRanges(css)
	if err != nil {
		t.Fatal(err)
	}
	light, dark := tokens(css, r[0]), tokens(css, r[1])
	navy := []string{"#13233F", "#1E3A66", "#2E4A78"}
	isNavy := func(v string) bool {
		return slices.ContainsFunc(navy, func(n string) bool { return strings.EqualFold(n, v) })
	}
	for k, v := range light {
		if !isNavy(v) {
			continue
		}
		if d, ok := dark[k]; !ok {
			t.Errorf("%s keeps the light theme's %s in dark", k, v)
		} else if isNavy(d) {
			t.Errorf("%s is %s in dark", k, d)
		}
	}
	for tok, like := range map[string]string{"--navy": "--bar-complete", "--head-field-line": "--field-line"} {
		if dark[tok] == "" || dark[tok] != dark[like] {
			t.Errorf("dark %s is %q, not %s's %q", tok, dark[tok], like, dark[like])
		}
	}
}

// A file input looks like the app's fields. Restore's was the browser's
// own ("Choose file | No file chosen"): the stylesheet gave it the field's
// box (32 px, as Restore beside it) but nothing to its button, which kept
// the browser's grey and system font, sitting at the top of the box (a file
// input does not centre its content; the rule's Script input had 8 px of
// top padding for it). The button is now the field's left part, its full
// height, in the app's button type on the panel's grey with the field's
// line after it (as the Pattern field's "/" parts); the file's name stands
// beside it, centred with it. Both file inputs (Restore, a script rule's
// Script) drop the field's left padding for it.
func TestFileInputsLikeFields(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, nil)
	if b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String(); !strings.Contains(b, `<input class="restorefile" type="file" name="backup"`) {
		t.Fatalf("restore panel:\n%s", between(b, `id="restore"`, "</form>"))
	}
	if b := e.do(t, "dora", "GET", "/admin/rules?new=1", nil, nil).Body.String(); !strings.Contains(b, `<div class="scriptrow"><span class="mono scriptname" title=""></span><input type="file" name="script"`) {
		t.Fatalf("script row:\n%s", between(b, `<div class="scriptrow">`, "</div>"))
	}
	css := stylesheet(t)
	for _, want := range []string{
		"input:not([type=checkbox]):not([type=radio]), select {\n  height: 40px; padding: 0 12px; border: 1px solid var(--field-line); background: var(--bg); color: var(--text);\n  font: 400 15px var(--sans);",
		"::file-selector-button {\n  height: 100%; margin: 0 12px 0 0; padding: 0 12px; border: 0; border-right: 1px solid var(--field-line);\n  background: var(--panel); color: var(--ink); font: 600 13px var(--sans); cursor: pointer;\n}",
		".panel.sys .restorefile { width: 280px; height: 32px; padding: 0; flex: none; align-self: center; font-size: 13px; }",
		".rf .scriptrow input[type=file] { flex: 1; width: auto; padding: 0; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %s", want)
		}
	}
	if strings.Count(css, "file-selector-button") != 1 || strings.Count(css, "input[type=file] {") != 1 || strings.Contains(css, "width: auto; padding-top: 8px;") {
		t.Error("style.css: another file input rule, or the Script input still pads its top")
	}
}
