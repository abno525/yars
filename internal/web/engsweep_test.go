package web

import (
	"strings"
	"testing"
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
	if !strings.Contains(css, ".tiles.sevtiles { grid-template-columns: repeat(6, minmax(0, 1fr)); grid-auto-flow: column; grid-auto-columns: minmax(0, 1fr); }") {
		t.Fatal("style.css: the severity tiles are not one row of six")
	}
}

// Export, New retest and New finding stand in the same place on every tab
// of an engagement. The board's New lead was a fourth button after them, so
// on the board they moved 140 px left. New lead has a slot of its own first
// in the row: the board fills it, the other tabs keep it empty (and the
// title column is as wide on every tab). New finding is secondary on the
// board (its primary is New lead), as before.
func TestEngHeadButtonsKeepTheirPlace(t *testing.T) {
	e := setup(t)
	headOf := func(path string) string {
		b := e.do(t, "dora", "GET", path, nil, nil).Body.String()
		return between(b, `<div class="actions">`, "</div>")
	}
	const rest = `<a class="btn secondary w128" href="/e/acme/export" aria-keyshortcuts="E">Export</a>
    <a class="btn secondary w128" href="/e/acme/retest/new">New retest</a>`
	for _, path := range []string{"/e/acme", "/e/acme/overview", "/e/acme/report", "/e/acme/settings"} {
		h := headOf(path)
		if !strings.HasPrefix(h, `<div class="actions">
    <span class="slot w128"></span>
    `+rest) || !strings.Contains(h, `<a class="btn primary w128" href="/e/acme/findings/new" aria-keyshortcuts="N">New finding</a>`) || strings.Contains(h, "New lead") {
			t.Errorf("%s head:\n%s", path, h)
		}
	}
	h := headOf("/e/acme/board")
	if !strings.HasPrefix(h, `<div class="actions">
    <a class="btn primary w128" href="/e/acme/board?new=1" hx-get="/e/acme/board?new=1" hx-target="#board" hx-swap="outerHTML" hx-push-url="true" aria-keyshortcuts="N">New lead</a>
    `+rest) || !strings.Contains(h, `<a class="btn secondary w128" href="/e/acme/findings/new">New finding</a>`) {
		t.Errorf("board head:\n%s", h)
	}
	// archived: the board keeps New lead's slot empty
	dora, _ := e.srv.Auth.Lookup("dora")
	if err := e.srv.Store.Archive("acme", dora); err != nil {
		t.Fatal(err)
	}
	if h := headOf("/e/acme/board"); !strings.HasPrefix(h, `<div class="actions">
    <span class="slot w128"></span>
    `+rest) || strings.Contains(h, "New lead") {
		t.Errorf("archived board head:\n%s", h)
	}
}
