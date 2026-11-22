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
