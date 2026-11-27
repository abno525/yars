package web

import (
	"strings"
	"testing"
)

// The retest result control is a segmented control like the others (40 px
// high, each option filling its segment, the dividers full height). Its form
// sits in the panel, so the panel's rule for the blocks of a panel's form
// (.panel > form > :not(.flush), 16 px 24 px) also reached its labels, which
// are the segments: they opt out with flush.
func TestRetestResultSegmentsHaveNoPanelMargin(t *testing.T) {
	e := setup(t)
	e.retestOfTest(t, "rt")
	b := e.do(t, "alice", "GET", "/e/rt/f/"+fdir, nil, nil).Body.String()
	form := between(b, `<form class="seg result-seg"`, "</form>")
	if n := strings.Count(form, "<label"); n != 3 || strings.Count(form, `<label class="flush">`) != n {
		t.Fatalf("the result segments are not flush:\n%s", form)
	}
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	if !strings.Contains(css, ".panel > form > :not(.panelhead):not(table):not(input[type=hidden]):not(.flush) { margin: 16px 24px; }") {
		t.Fatal("style.css: the panel's form margin rule no longer leaves .flush out")
	}
	// nothing moves when a result is chosen or refused: the red edge of a
	// panel that needs one does not change its border's width, and the
	// error has its slot whether or not there is one
	if rule := between(css, ".panel.resultp.needs {", "}"); strings.Contains(rule, "border:") || strings.Contains(rule, "border-width") {
		t.Errorf(".panel.resultp.needs changes the border's width: %q", rule)
	}
	// the slot is flush, or the panel's generic child margin (16 px 24 px,
	// a stronger selector) wins over its own 8 px
	panel := between(b, `<section class="panel resultp`, "</section>")
	if !strings.Contains(panel, `<div class="errslot flush">`) {
		t.Errorf("no reserved flush error slot:\n%s", panel)
	}
	if !strings.Contains(css, ".resultp > .errslot { margin: 8px 24px 0; }") {
		t.Errorf("style.css lacks the error slot's margin")
	}
}
