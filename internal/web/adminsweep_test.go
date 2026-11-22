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

// Admin › System: a wide stat takes the rest of its row. Wide stats were
// two cells (520 px) and always end their row, so Last prune and Data
// folder sat beside three empty columns (Data folder cut short) and
// Restore's Folder and Operations' Last operation beside one. The cells
// before them keep their 256 px places, so every row stays in line with
// the five-cell rows (M35); a row of plain cells is unchanged.
func TestSystemWideStatsFillTheirRow(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	wide := 0
	for _, row := range strings.Split(b, `<div class="stats">`)[1:] {
		row = row[:strings.Index(row, "\n    </div>")]
		if i := strings.Index(row, `<div class="st wide">`); i >= 0 {
			wide++
			if strings.Contains(row[i+1:], `<div class="st`) {
				t.Errorf("a wide stat before the end of its row:\n%s", row)
			}
		}
	}
	if wide != 4 {
		t.Fatalf("%d wide stats (Last prune, Folder, Last operation, Data folder)", wide)
	}
	css := stylesheet(t)
	for _, want := range []string{
		// a wide stat ends where five cells end (5 x 256 + 4 x 8), not at the
		// panel's edge, which moves with the window and the scrollbar
		".stats { display: flex; gap: 8px; max-width: 1312px; }",
		".st { width: 256px; height: 72px; flex: 0 1 256px;",
		".st.wide { width: 520px; flex: 1 1 520px; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %s", want)
		}
	}
}

// Admin › Rules' test bench. Its fields stood 44 px in from the panel's
// side where the New rule panel beside it has them at 20: the bench's form
// is the panel's child (12 px 20 px, a compact panel's), and its own
// children took the generic margin of a panel's form children too (.panel
// > form > *, 16 px 24 px), as the Team add row's did; they are flush now,
// as there, and the form's 12 px gap stands between them, as between the
// rule's fields. Try (96 px) stood beside Run on engagement (176 px); side
// by side buttons share a width (Cancel and Save, the title rows), so Try
// is 176 too. The Hits table showed only its header before a run and after
// one with no hits; it shows the one empty row ("—"), as every table, and
// so does Run on engagement's.
func TestRuleBenchLikeTheRuleForm(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, nil)
	b := e.do(t, "dora", "GET", "/admin/rules", nil, nil).Body.String()
	form := between(b, `<form class="benchform"`, "</form>")
	for _, want := range []string{
		`<label class="rf flush">Rule<select name="rule">`,
		`<div class="rgrid flush">`,
		`<div class="benchrun flush"><button class="btn secondary sm w176">Try</button><button class="btn primary sm w176" name="all" value="1">Run on engagement</button></div>`,
	} {
		if !strings.Contains(form, want) {
			t.Errorf("bench form lacks %s:\n%s", want, form)
		}
	}
	empty := `<tr class="emptyrow"><td colspan="4">—</td></tr>`
	if n := checkEmptyRows(t, "/admin/rules", b); n != 1 || !strings.Contains(between(b, `<div class="benchout flush" id="bench-out">`, "</table>"), empty) {
		t.Errorf("%d empty tables; Hits before a run:\n%s", n, between(b, `<div class="benchout flush" id="bench-out">`, "</table>"))
	}
	ref, err := e.srv.Store.CreateFinding("acme", "Missing HSTS header", e.authorOf(wAlice))
	if err != nil {
		t.Fatal(err)
	}
	out := e.do(t, "dora", "GET", "/admin/rules/bench?rule=title-word&eng=acme&fid="+ref.Dir, nil, nil).Body.String()
	if !strings.Contains(out, `<span class="badge0">0</span>`) || !strings.Contains(out, empty) {
		t.Errorf("Hits after a run with none:\n%s", out)
	}
	css := stylesheet(t)
	for _, want := range []string{
		".panel > :not(.panelhead):not(table):not(.flush), .panel > form > :not(.panelhead):not(table):not(input[type=hidden]):not(.flush) { margin: 16px 24px; }",
		".panel.compact > :not(.panelhead):not(.flush) { margin: 12px 20px; }",
		".rfields { display: flex; flex-direction: column; gap: 12px; }",
		".benchform { display: flex; flex-direction: column; gap: 12px; }",
		".benchrun { display: flex; justify-content: flex-end; }",
		".w176 { width: 176px; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %s", want)
		}
	}
}

// Admin › Structure. Its four lists stood in a grid of three columns, so
// Report sections sat alone in a second row, two thirds of it empty; two
// columns hold the four, in their order, with no empty place (four to a
// row would leave an item 137 px, too narrow for "Executive summary").
// Each list's add row had its input 56 px wider than the items' above
// (and, in Severities, 20 px wider on the left too): after an item's input
// come the count (40) and ↑ ↓ × (32 each), 6 px apart, 160 px; after the
// add row's, Add (96) 8 px on, 104. Add is 152, so 8 + 152 makes 160 and
// it stands under the count and the three buttons; where items show a
// colour swatch (14, 6 on), the add row keeps its place empty.
func TestStructureListsFillTheGrid(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/admin/structure", nil, nil).Body.String()
	grid := between(b, `<div class="structgrid">`, `<section class="panel">`)
	if n := strings.Count(grid, `<section class="panel compact slist">`); n != 4 {
		t.Fatalf("%d lists:\n%s", n, grid)
	}
	for _, key := range []string{"section", "detail", "severity", "report"} {
		if !strings.Contains(grid, `<button class="btn secondary sm w152" name="op" value="add:`+key+`">Add</button>`) {
			t.Errorf("%s add row:\n%s", key, between(grid, `<input class="grow" name="new_`+key+`"`, "</div>"))
		}
	}
	if !strings.Contains(between(grid, "Severities", "</section>"), `<span class="sw seg-critical"></span>`) {
		t.Fatalf("severities show no swatch:\n%s", between(grid, "Severities", "</section>"))
	}
	css := stylesheet(t)
	for _, want := range []string{
		".structgrid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; align-items: start; }",
		".sitem { min-height: 52px; padding: 0 12px 0 16px; display: flex; align-items: center; gap: 6px;",
		".sitem .sw { width: 14px; height: 14px;",
		".sused { width: 40px; flex: none;",
		".btn.icon.sm { width: 32px; }",
		".lock { width: 32px; height: 32px; flex: none;",
		".sadd { min-height: 56px; padding: 0 12px 0 16px; display: flex; align-items: center; gap: 8px;",
		".w152 { width: 152px; }",
		".slist:has(.sitem .sw) .sadd { padding-left: 36px; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %s", want)
		}
	}
}
