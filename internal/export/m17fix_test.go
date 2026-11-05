package export

import (
	"context"
	"strings"
	"testing"
)

func reportInput(t *testing.T) Input {
	in := input(t)
	in.Report = []ReportText{
		{Name: "Executive summary", Body: "We found **three** issues."},
		{Name: "Scope", Body: "The web portal.\n\n![x](attachments/shot.png)"},
		{Name: "Methodology", Body: "  \n"},
	}
	return in
}

// The text written in the engagement's Report tab is in every report.
func TestReportSectionsExported(t *testing.T) {
	in := reportInput(t)
	x := Report(in)
	sum := strings.Index(x, `<h1 id="rp-summary">Executive summary</h1>`)
	text := strings.Index(x, "We found <strong>three</strong> issues.")
	counts := strings.Index(x, `<table class="rp-counts">`)
	if sum < 0 || text < sum || counts < text {
		t.Fatalf("executive summary text (%d %d %d):\n%s", sum, text, counts, x)
	}
	scope := strings.Index(x, "<h2>Scope</h2>\n<p>The web portal.</p>")
	if scope < strings.Index(x, `id="rp-scope"`) || scope > strings.Index(x, `class="rp-kv"`) {
		t.Fatalf("scope:\n%s", x)
	}
	if strings.Contains(x, "Methodology") || strings.Contains(x, "<img") {
		t.Fatalf("empty section or image:\n%s", x)
	}

	h := XHTML(in, false)
	if !strings.Contains(h, "<h1>Executive summary</h1>\n<p>We found <strong>three</strong> issues.</p>") || !strings.Contains(h, "<h1>Scope</h1>") ||
		strings.Index(h, "<h1>Scope</h1>") > strings.Index(h, "<h1>F-001") {
		t.Fatalf("xhtml:\n%s", h)
	}
}

func TestReportSectionsScript(t *testing.T) {
	r, dir := runner(t, "")
	writeFile(t, dir, "dump.sh", "#!/bin/sh\ncat\n", 0o755)
	res, err := r.Run(context.Background(), Exporter{ID: "s", Type: "script", Script: "dump.sh", Extension: "json"}, reportInput(t))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(res.Data), `"report":[{"name":"Executive summary","body":"We found **three** issues."`) {
		t.Fatalf("script input:\n%s", res.Data)
	}
}
