package web

import (
	"strings"
	"testing"

	"yars/internal/store"
)

// The retest result control is a segmented control like the others (40 px
// high, each option filling its segment, the dividers full height). Its form
// sits in the panel, so the panel's rule for the blocks of a panel's form
// (.panel > form > :not(.flush), 16 px 24 px) also reached its labels, which
// are the segments: they opt out with flush.
func TestRetestResultSegmentsHaveNoPanelMargin(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{fdir}, "", wDora); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/rt/f/"+fdir, nil, nil).Body.String()
	form := between(b, `<form class="seg result-seg"`, "</form>")
	if n := strings.Count(form, "<label"); n != 3 || strings.Count(form, `<label class="flush">`) != n {
		t.Fatalf("the result segments are not flush:\n%s", form)
	}
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	if !strings.Contains(css, ".panel > form > :not(.panelhead):not(table):not(input[type=hidden]):not(.flush) { margin: 16px 24px; }") {
		t.Fatal("style.css: the panel's form margin rule no longer leaves .flush out")
	}
}
