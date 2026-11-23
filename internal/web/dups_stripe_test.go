package web

import (
	"strings"
	"testing"
)

// The Possible duplicates panel's orange stripe runs its whole height. It
// was an inset box-shadow, which is painted under the panel's children, so
// the table (its background) and the header row (theirs) covered it from the
// header to the last row. It is drawn above them instead.
func TestDupsStripeAboveTable(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", "/e/acme/findings/new", nil, nil).Body.String(); !strings.Contains(b, `<section class="panel compact dups" id="dups"`) || !strings.Contains(b, `<table class="table dtable">`) {
		t.Fatalf("no duplicates table:\n%s", b)
	}
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	rule := between(css, "\n.dups {", "}")
	if rule == "" || strings.Contains(rule, "box-shadow") || !strings.Contains(rule, "position: relative;") {
		t.Fatalf("style.css: .dups is %q", rule)
	}
	if !strings.Contains(css, `.dups::before { content: ""; position: absolute; top: 0; bottom: 0; left: 0; width: 4px; background: var(--accent); pointer-events: none; }`) {
		t.Fatal("style.css: no stripe drawn above the duplicates table")
	}
}

// The lists that scroll inside New finding keep the scrollbar's room
// (scrollbar-gutter: stable: nothing moves when they start to scroll); the
// header band runs on into that room, painted in the list's own background
// under the table, as the top bar's colours are in the page's gutter.
func TestScrollListHeaderBandFillsGutter(t *testing.T) {
	e := setup(t)
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	want := ".tplscroll, .newf .dups .dscroll { background: linear-gradient(var(--panel) 43px, var(--line) 43px, var(--line) 44px, transparent 44px) no-repeat; }"
	if !strings.Contains(css, want) {
		t.Fatal("style.css: the header band stops short of the lists' scrollbar room")
	}
}
