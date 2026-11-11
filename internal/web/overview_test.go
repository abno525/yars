package web

import (
	"regexp"
	"strings"
	"testing"
)

// R1 item 1: the Overview shows tiles and bars only, no legends and no
// chart tables repeating the same numbers.
func TestOverviewHasNoLegendOrTables(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme/overview", nil, nil).Body.String()
	main := between(b, "<main>", "</main>")
	if !strings.Contains(main, `class="tiles"`) || !strings.Contains(main, `class="bar"`) {
		t.Fatalf("overview lacks tiles or bars:\n%s", main)
	}
	if strings.Contains(main, `class="legend"`) || strings.Contains(main, `class="sevchart`) {
		t.Fatalf("overview repeats its numbers:\n%s", main)
	}
}

// R10: a draft without a severity is its own segment of the severity bar,
// titled "— · N".
func TestOverviewUnscoredSegment(t *testing.T) {
	e := setup(t) // F-001 is a new draft without severity
	b := e.do(t, "alice", "GET", "/e/acme/overview", nil, nil).Body.String()
	if !regexp.MustCompile(`<rect class="seg-none"[^>]*><title>— · 1</title>`).MatchString(b) {
		t.Fatalf("no unscored segment:\n%s", between(b, `aria-label="Engagement progress"`, "</section>"))
	}
}

// The numbers the legends and tables repeated live in a By severity panel
// of tiles: one per configured severity, and "—" for unscored drafts when
// there are any.
func TestOverviewSeverityTiles(t *testing.T) {
	e := setup(t)
	tilesOf := func() string {
		b := e.do(t, "alice", "GET", "/e/acme/overview", nil, nil).Body.String()
		return between(b, "<h2>By severity</h2>", "</section>")
	}
	tiles := tilesOf()
	for _, sev := range []string{"Critical", "High", "Medium", "Low", "Info"} {
		if !strings.Contains(tiles, `<span class="tl">`+sev+`</span>`) {
			t.Errorf("no %s tile:\n%s", sev, tiles)
		}
	}
	if !strings.Contains(tiles, `<span class="tv">1</span><span class="tl">—</span>`) {
		t.Fatalf("no unscored tile:\n%s", tiles)
	}
	e.toVerification(t) // F-001 gets a severity
	if tiles := tilesOf(); strings.Contains(tiles, `<span class="tl">—</span>`) {
		t.Fatalf("an unscored tile without unscored findings:\n%s", tiles)
	}
}

// R10: the Report tab's total counts the findings that have a severity, so
// its rows add up.
func TestReportTotalsAddUp(t *testing.T) {
	e := setup(t)
	e.toVerification(t) // F-001 high
	if _, err := e.srv.Store.CreateFinding("acme", "Open redirect", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/acme/report", nil, nil).Body.String()
	if sum, _ := e.srv.Index.Summary("acme"); sum.Total != 2 {
		t.Fatalf("fixture: %d findings", sum.Total)
	}
	if !strings.Contains(b, `<h2>Severity totals</h2><span class="mono">1</span>`) {
		t.Fatalf("report total:\n%s", between(b, "Severity totals", "</section>"))
	}
}
