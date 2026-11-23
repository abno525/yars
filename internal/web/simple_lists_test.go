package web

import (
	"regexp"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/store"
	"yars/internal/workflow"
)

var (
	sAnna = config.User{Username: "anna", Role: "director", IsAdmin: true}
	sBen  = config.User{Username: "ben", Role: "director"}
)

// completeAs gives a draft of acme a severity and completes it as u.
func (e *env) completeAs(t *testing.T, dir string, u config.User) {
	t.Helper()
	st := e.srv.Store
	if err := st.UpdateSeverity("acme", dir, "high", "", u); err != nil {
		t.Fatal(err)
	}
	if err := st.Transition("acme", dir, workflow.Complete, "", u); err != nil {
		t.Fatal(err)
	}
}

var filterRe = regexp.MustCompile(`id="flt-([a-z-]+)" aria-keyshortcuts="(\d)" href="[^"]*" hx-get="[^"]*" hx-target="#findings" hx-swap="outerHTML" hx-push-url="true">([^<]+)</a>`)

// filtersOf lists the findings list's status filters as "key digit label".
func filtersOf(b string) []string {
	var out []string
	for _, m := range filterRe.FindAllStringSubmatch(between(b, `aria-label="Status"`, "</nav>"), -1) {
		out = append(out, m[1]+" "+m[2]+" "+m[3])
	}
	return out
}

// The simple workflow's findings list filters by its own states: All, Draft,
// Complete, Reported and Withdrawn on keys 1 to 5, with neither verification
// nor signed off.
func TestSimpleStatusFilters(t *testing.T) {
	e := setupSimple(t)
	d2 := e.second(t, "ben")
	e.completeAs(t, d2, sBen)
	b := e.do(t, "anna", "GET", "/e/acme", nil, nil).Body.String()
	want := []string{"all 1 All · 2", "draft 2 Draft · 1", "complete 3 Complete · 1", "reported 4 Reported · 0", "withdrawn 5 Withdrawn · 0"}
	if got := filtersOf(b); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("filters %q, want %q", got, want)
	}
	for _, gone := range []string{"flt-verification", "flt-signed-off", "Verification ·", "Signed off ·"} {
		if strings.Contains(b, gone) {
			t.Errorf("list has %q", gone)
		}
	}
	// a filter lists its findings and is the one marked on
	f := e.do(t, "anna", "GET", "/e/acme?status=complete", nil, nil).Body.String()
	if !strings.Contains(f, `class="on" id="flt-complete"`) || frow(f, d2) == "" || frow(f, fdir) != "" {
		t.Fatalf("complete filter:\n%s", between(f, `id="findings"`, "</table>"))
	}
	// the standard list keeps its seven
	std := setup(t)
	if got := filtersOf(std.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String()); len(got) != 7 || got[2] != "verification 3 Verification · 0" || got[3] != "signed-off 4 Signed off · 0" {
		t.Fatalf("standard filters %q", got)
	}
}

// The simple workflow has no reviewers: the findings list has no Reviewers
// column, its header or its cells, and the empty row and Load more span the
// columns left.
func TestSimpleNoReviewersColumn(t *testing.T) {
	e := setupSimple(t)
	e.srv.pageSize = 1
	e.second(t, "ben")
	b := e.do(t, "anna", "GET", "/e/acme", nil, nil).Body.String()
	tbl := between(b, `<table class="table findings"`, "</table>")
	for _, gone := range []string{"col-reviewers", "sort-reviewers", ">Reviewers", `class="revs"`, `class="rvs"`} {
		if strings.Contains(tbl, gone) {
			t.Errorf("findings table has %q:\n%s", gone, tbl)
		}
	}
	// pick, ID, Title, Severity, CVSS, Status, Chat, Author
	if n := strings.Count(between(tbl, "<thead>", "</thead>"), "<th "); n != 8 {
		t.Errorf("%d header cells:\n%s", n, tbl)
	}
	if !strings.Contains(tbl, `<tr class="more" id="findings-more"><td colspan="8">`) {
		t.Errorf("Load more colspan:\n%s", tbl)
	}
	if r := frow(b, fdir); strings.Count(r, "<td") != 8 {
		t.Errorf("row cells: %s", r)
	}
	empty := e.do(t, "anna", "GET", "/e/acme?status=reported", nil, nil).Body.String()
	if !strings.Contains(empty, `<tr class="emptyrow"><td colspan="8">—</td></tr>`) {
		t.Fatalf("empty row:\n%s", between(empty, `<table class="table findings"`, "</table>"))
	}
	// the standard list keeps the column
	std := setup(t)
	sb := std.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String()
	if !strings.Contains(sb, `<th class="col-reviewers">`) || !strings.Contains(frow(sb, fdir), `class="revs"`) {
		t.Fatal("standard list lost its Reviewers column")
	}
	// a retest's list: its Result column, still no Reviewers
	if err := e.srv.Store.CreateRetest(store.Engagement{ID: "acme-rt", Name: "ACME retest"}, "acme", []string{fdir}, "", sAnna); err != nil {
		t.Fatal(err)
	}
	rt := between(e.do(t, "anna", "GET", "/e/acme-rt", nil, nil).Body.String(), "<thead>", "</thead>")
	if !strings.Contains(rt, `<th class="col-result">`) || strings.Contains(rt, "col-reviewers") || strings.Count(rt, "<th ") != 9 {
		t.Fatalf("retest header:\n%s", rt)
	}
}

var legendRe = regexp.MustCompile(`<span class="sw seg-([a-z-]+)"></span><span class="lgname">([^<]+)</span><span class="n">(\d+)</span>`)

// legendOf lists a legend's entries as "key label count".
func legendOf(b string) []string {
	var out []string
	for _, m := range legendRe.FindAllStringSubmatch(b, -1) {
		out = append(out, m[1]+" "+m[2]+" "+m[3])
	}
	return out
}

// keysOf lists a bar's legend keys.
func keysOf(v barView) []string {
	var out []string
	for _, s := range v.Legend {
		out = append(out, s.Key)
	}
	return out
}

// The progress bars and their legends follow the simple workflow: draft,
// complete and reported on the findings page, the home table and the
// Overview, never verification or signed off.
func TestSimpleProgressBars(t *testing.T) {
	e := setupSimple(t)
	st := e.srv.Store
	d2 := e.second(t, "ben")
	e.completeAs(t, d2, sBen)
	if err := st.Transition("acme", d2, workflow.Report, "", sBen); err != nil {
		t.Fatal(err)
	}
	e.completeAs(t, e.second(t, "anna"), sAnna)
	gone := []string{"seg-verification", "seg-signed-off", "Verification", "Signed off", "signed off"}

	b := e.do(t, "anna", "GET", "/e/acme", nil, nil).Body.String()
	bars := between(b, `id="engbars"`, "</section>")
	if got := legendOf(between(bars, ">Progress<", ">By severity<")); strings.Join(got, ",") != "draft Draft 1,complete Complete 1,reported Reported 1" {
		t.Fatalf("findings page legend %q:\n%s", got, bars)
	}
	if !strings.Contains(bars, ">1 of 3 reported<") {
		t.Fatalf("findings page count:\n%s", bars)
	}
	for _, g := range gone {
		if strings.Contains(bars, g) {
			t.Errorf("findings page bars have %q", g)
		}
	}

	// the home table counts the reported ones; its row's bars are the same
	home := e.do(t, "anna", "GET", "/", nil, nil).Body.String()
	if r := between(home, `data-eng="acme"`, "</tr>"); !strings.Contains(r, ">1 of 3<") {
		t.Fatalf("home row:\n%s", r)
	}
	rows, err := e.srv.engRows([]store.Engagement{{ID: "acme"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := keysOf(rows[0].Bars.Progress); strings.Join(got, ",") != "draft,complete,reported" {
		t.Fatalf("home bar keys %q", got)
	}

	// the Overview: one segment per state with findings, none other
	ov := between(e.do(t, "anna", "GET", "/e/acme/overview", nil, nil).Body.String(), `aria-label="Engagement progress"`, "</section>")
	for _, k := range []string{"draft", "complete", "reported"} {
		if !strings.Contains(ov, `<rect class="seg-`+k+`"`) {
			t.Errorf("Overview has no %s segment:\n%s", k, ov)
		}
	}
	for _, g := range gone {
		if strings.Contains(ov, g) {
			t.Errorf("Overview bars have %q", g)
		}
	}
	sum, err := e.srv.Index.Summary("acme")
	if err != nil {
		t.Fatal(err)
	}
	if got := keysOf(overviewBars(sum).Progress); strings.Join(got, ",") != "draft,complete,reported" {
		t.Fatalf("Overview bar keys %q", got)
	}
}
