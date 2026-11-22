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
