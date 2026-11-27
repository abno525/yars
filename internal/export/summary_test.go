package export

import (
	"strings"
	"testing"
)

// The first report section is the summary, whatever it is called: its text
// stands under the report's first heading, above the severity counts, and is
// not repeated in the next chapter. An empty first section leaves the
// summary empty: the second one does not move up.
func TestReportSummaryIsTheFirstReportSection(t *testing.T) {
	in := input(t)
	in.Report = []ReportText{{Name: "Management summary", Body: "Three findings, one of them high."}, {Name: "Scope", Body: "The web portal."}, {Name: "Executive summary", Body: "An old name, further down."}}
	x := Report(in)
	head, counts, scope := strings.Index(x, `<h1 id="rp-summary">Executive summary</h1>`), strings.Index(x, `<table class="rp-counts">`), strings.Index(x, `<h1 id="rp-scope">`)
	if head < 0 || counts < head || scope < counts {
		t.Fatalf("the report's chapters moved: %d %d %d", head, counts, scope)
	}
	if i := strings.Index(x, "Three findings, one of them high."); i < head || i > counts {
		t.Errorf("the first report section is not above the counts (at %d, heading %d, counts %d)", i, head, counts)
	}
	if strings.Count(x, "Three findings, one of them high.") != 1 || strings.Contains(x, "<h2>Management summary</h2>") {
		t.Error("the summary is repeated under Scope and overview")
	}
	for _, later := range []string{"<h2>Scope</h2>\n<p>The web portal.</p>", "<h2>Executive summary</h2>\n<p>An old name, further down.</p>"} {
		if i := strings.Index(x, later); i < scope {
			t.Errorf("%q is not under Scope and overview (at %d)", later, i)
		}
	}

	// an empty first section: nothing above the counts
	in.Report[0].Body = "\n"
	x = Report(in)
	head, counts = strings.Index(x, `<h1 id="rp-summary">`), strings.Index(x, `<table class="rp-counts">`)
	if between := x[head:counts]; strings.Contains(between, "<p>") {
		t.Errorf("an empty first section let another one move up:\n%s", between)
	}
	if !strings.Contains(x, "<h2>Scope</h2>") || strings.Contains(x, "<h2>Management summary</h2>") {
		t.Error("the sections under Scope and overview changed")
	}
}
