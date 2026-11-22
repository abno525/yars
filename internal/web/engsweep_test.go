package web

import (
	"net/url"
	"strings"
	"testing"

	"yars/internal/export"
	"yars/internal/index"
)

// The Overview's By severity tiles stand in one row. They shared the
// Totals' four-column grid, so the fifth (Info) wrapped alone onto a second
// row. Six columns: the five CVSS severities and the slot of the unscored
// "—" tile, which fills it when a draft has no severity, so no tile moves
// when it comes or goes; more configured severities add columns, still in
// one row.
func TestOverviewSeverityTilesOneRow(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme/overview", nil, nil).Body.String()
	if !strings.Contains(between(b, "<h2>By severity</h2>", "</section>"), `<div class="tiles sevtiles">`) {
		t.Fatalf("By severity panel:\n%s", between(b, "<h2>By severity</h2>", "</section>"))
	}
	if !strings.Contains(between(b, "<h2>Totals</h2>", "</section>"), `<div class="tiles">`) {
		t.Fatalf("Totals panel:\n%s", between(b, "<h2>Totals</h2>", "</section>"))
	}
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	if !strings.Contains(css, ".tiles.sevtiles { grid-template-columns: none; grid-auto-flow: column; grid-auto-columns: minmax(0, 1fr); }") {
		t.Fatal("style.css: the severity tiles are not one row, a column per tile")
	}
	// the "—" tile's place is there whether or not a draft is unscored (an
	// empty slot), so the row has a column per severity plus one in every
	// state, whatever the severities configured
	tiles := func() (n, slots int) {
		p := between(e.do(t, "alice", "GET", "/e/acme/overview", nil, nil).Body.String(), `<div class="tiles sevtiles">`, "</section>")
		return strings.Count(p, `<div class="tile">`), strings.Count(p, `<div class="tileslot"></div>`)
	}
	sevs := len(e.srv.Store.Config().Severities)
	rows, err := e.srv.Index.Rows(index.Query{EngID: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows { // every finding scored: no "—" tile
		if r.Severity == "" {
			if err := e.srv.Store.UpdateSeverity("acme", r.Dir, "low", "", wDora); err != nil {
				t.Fatal(err)
			}
		}
	}
	if n, slots := tiles(); n != sevs || slots != 1 {
		t.Fatalf("no unscored draft: %d tiles, %d slots (want %d and 1)", n, slots, sevs)
	}
	if _, err := e.srv.Store.CreateFinding("acme", "Unscored", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	if n, slots := tiles(); n != sevs+1 || slots != 0 {
		t.Fatalf("an unscored draft: %d tiles, %d slots (want %d and 0)", n, slots, sevs+1)
	}
}

// Export, New retest and New finding stand in the same place on every tab
// of an engagement. The board's New lead was a fourth button after them, so
// on the board they moved 140 px left. New lead keeps its place, last; the
// other tabs keep that place as an empty slot (fill empty slots, do not
// reorder). New finding is secondary on the board (its primary is New
// lead), as before.
func TestEngHeadButtonsKeepTheirPlace(t *testing.T) {
	e := setup(t)
	headOf := func(path string) string {
		b := e.do(t, "dora", "GET", path, nil, nil).Body.String()
		return strings.TrimRight(between(b, `<div class="actions">`, "</div>"), " \n")
	}
	const first = `<div class="actions">
    <a class="btn secondary w128" href="/e/acme/export" aria-keyshortcuts="E">Export</a>
    <a class="btn secondary w128" href="/e/acme/retest/new">New retest</a>`
	const slot = `<span class="slot w128"></span>`
	for _, path := range []string{"/e/acme", "/e/acme/overview", "/e/acme/report", "/e/acme/settings"} {
		h := headOf(path)
		if !strings.HasPrefix(h, first) || !strings.HasSuffix(h, `<a class="btn primary w128" href="/e/acme/findings/new" aria-keyshortcuts="N">New finding</a>
    `+slot) {
			t.Errorf("%s head:\n%s", path, h)
		}
	}
	h := headOf("/e/acme/board")
	if !strings.HasPrefix(h, first) || !strings.HasSuffix(h, `<a class="btn secondary w128" href="/e/acme/findings/new">New finding</a>
    <a class="btn primary w128" href="/e/acme/board?new=1" hx-get="/e/acme/board?new=1" hx-target="#board" hx-swap="outerHTML" hx-push-url="true" aria-keyshortcuts="N">New lead</a>`) {
		t.Errorf("board head:\n%s", h)
	}
	// archived: the board keeps New lead's slot empty
	dora, _ := e.srv.Auth.Lookup("dora")
	if err := e.srv.Store.Archive("acme", dora); err != nil {
		t.Fatal(err)
	}
	if h := headOf("/e/acme/board"); !strings.HasPrefix(h, first) || !strings.HasSuffix(h, slot) || strings.Contains(h, "New lead") {
		t.Errorf("archived board head:\n%s", h)
	}
}

// The team board fits the window: only its lists scroll. Both panes were
// 760 px, so at 1440 x 900 the page scrolled 152 px. The board is the
// window less what stands above and below it: the 64 px top bar, main's
// 24 px top padding, the title (28 px heading at 1.2, 8 gap, 21 px line:
// 62.6), a 24 px gap, the 44 px tabs and their 1 px line, a 24 px gap, and
// main's 48 px bottom padding: 291.6 px; an archived engagement's 48 px bar
// and its 24 px gap take 72 more. With no lead open the thread pane shows
// a head with the muted "—" (as History's empty change panel), not a blank
// box.
func TestTeamBoardFitsWindow(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme/board", nil, nil).Body.String()
	if !strings.Contains(b, `<section class="tbthread empty" aria-label="Thread"><div class="tbhead"><div class="tbtitle"><h2 class="muted">—</h2></div></div></section>`) {
		t.Fatalf("empty thread pane:\n%s", between(b, `<div id="board"`, "</main>"))
	}
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	for _, want := range []string{
		"position: sticky; top: 0; z-index: 10; height: 64px;",
		"main { max-width: 1760px; margin: 0 auto; padding: 24px 32px 48px; display: flex; flex-direction: column; gap: 24px; }",
		"h1 { margin: 0; font-size: 28px; font-weight: 700; line-height: 1.2; }",
		".titlecol { display: flex; flex-direction: column; gap: 8px;",
		"min-height: 21px; }",
		".etabs { display: flex; border-bottom: 1px solid var(--line); }",
		"width: 160px; height: 44px;",
		"min-height: 48px; padding: 0 16px; display: flex; align-items: center; gap: 12px;",
		".tboard { --tb-h: calc(100vh - 292px); height: var(--tb-h);",
		".archbar ~ .tboard { --tb-h: calc(100vh - 364px); }",
		".tbthread { height: var(--tb-h);",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %s", want)
		}
	}
	if strings.Contains(css, ".tbthread.empty {") {
		t.Error("style.css: the empty thread pane is still padded and centred")
	}
}

// The Team panel's add row lines up with the table above it: the select
// starts where the User column's text does and ends where the Role
// column's does, Add stands under Remove. The select and Add took the
// generic margin of a panel's form children (.panel > form > *, 16 px 24
// px), so both sat inward and the row was 88 px high. With everyone on the
// team the select is disabled and shows the muted "—", not an empty box.
func TestTeamAddRowLinesUp(t *testing.T) {
	e := setup(t)
	rowOf := func() string {
		b := e.do(t, "dora", "GET", "/e/acme/settings", nil, nil).Body.String()
		return between(b, `<form class="inline flush addrow"`, "</form>")
	}
	r := rowOf()
	if !strings.Contains(r, `<select class="grow flush" name="user" aria-label="Add person" aria-keyshortcuts="A"><option value=`) || !strings.Contains(r, `<button class="btn primary sm w96 flush">Add</button>`) {
		t.Fatalf("add row with people to add:\n%s", r)
	}
	for _, u := range []string{"alice", "bob", "carol", "dora"} {
		e.do(t, "dora", "POST", "/e/acme/settings/team", url.Values{"user": {u}}, nil)
	}
	r = rowOf()
	// disabled, it gives up its key, so the ? list does not offer a (as the
	// board's disabled controls do)
	if !strings.Contains(r, `<select class="grow flush" name="user" aria-label="Add person" disabled><option>—</option></select>`) || !strings.Contains(r, `<button class="btn primary sm w96 flush" disabled>Add</button>`) {
		t.Fatalf("add row with everyone on the team:\n%s", r)
	}
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	for _, want := range []string{
		".table td { height: 52px; padding: 0 16px;",
		".table th.c-role, .table th.c-state, .table th.c-check, .table th.c-svc { width: 152px; }",
		".table th.c-act, .table th.c-act2 { width: 144px; }",
		// 16: the User column's padding; 32 right: Add (96) ends 128 - 96 from
		// the Action column's start (16 in); 32 gap: Role's padding and Action's
		"form.addrow { padding: 12px 32px 12px 16px; gap: 32px; border-top: 1px solid var(--line); background: var(--panel); }",
		".addrow select:disabled { border-color: var(--line-soft); color: var(--off-fg); }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %s", want)
		}
	}
}

// Export's title row: Preview and Destinations are the title row's
// secondary buttons, both 128 px, as every other page's (Export, New
// retest, Cancel, Back). Preview was the only full-size ghost button of
// any page (pale border) and Destinations 152 px. Who may not set up
// destinations keeps a 128 px slot.
func TestExportHeadButtonsAlike(t *testing.T) {
	e := setup(t)
	e.srv.Export = &export.Runner{Dir: t.TempDir()} // exporting on, no destinations yet
	b := e.do(t, "dora", "GET", "/e/acme/export", nil, nil).Body.String()
	h := between(b, `<div class="actions">`, "</div>")
	if !strings.Contains(h, `<button class="btn secondary w128" formaction="/e/acme/export/preview" formmethod="get" aria-keyshortcuts="P">Preview</button>
      <a class="btn secondary w128" href="/e/acme/export/setup">Destinations</a>`) {
		t.Fatalf("director's export head:\n%s", h)
	}
	b = e.do(t, "alice", "GET", "/e/acme/export", nil, nil).Body.String()
	if h := between(b, `<div class="actions">`, "</div>"); !strings.Contains(h, `aria-keyshortcuts="P">Preview</button>
      <span class="slot w128"></span>`) {
		t.Fatalf("pentester's export head:\n%s", h)
	}
}
