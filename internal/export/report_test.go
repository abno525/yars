package export

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/store"
)

func TestReportHTML(t *testing.T) {
	in := input(t)
	in.Engagement.Start, in.Engagement.End = "2026-11-04", "2026-11-07"
	x := Report(in)
	for _, want := range []string{
		`<div class="rp-cover">`, `<span class="rp-title">ACME Web</span>`, `<span class="rp-sub">ACME · 2026-11-04 – 2026-11-07</span>`,
		`<h1 id="rp-summary">Executive summary</h1>`, `<h1 id="rp-scope">Scope and overview</h1>`, `<h1 id="rp-findings">Findings</h1>`,
		`<div class="rp-fhead sevbar-high" id="rp-F-001" data-bg="C4520F" data-fg="FFFFFF" data-sev="high">`,
		`<span class="rp-vec">CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N</span>`, `<span class="rp-score">7.4</span>`,
		`<span class="rp-sev tag sev-high" data-bg="C4520F" data-fg="FFFFFF">high</span>`,
		`<tr><th>Location</th><td>https://x/login<br />param user</td></tr>`,
		`<h2>Description</h2>`,
	} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %q", want)
		}
	}
	// severity counts: one high, one medium, one low, zeros kept
	if !strings.Contains(x, `<td class="num">1</td><td class="num">1</td><td class="num">1</td><td class="num">0</td>`) &&
		!strings.Contains(x, `<td class="num">0</td><td class="num">1</td><td class="num">1</td><td class="num">1</td><td class="num">0</td>`) {
		t.Errorf("counts:\n%s", x)
	}
	if strings.Index(x, `id="rp-F-001"`) > strings.Index(x, `id="rp-F-003"`) || strings.Index(x, `id="rp-F-003"`) > strings.Index(x, `id="rp-F-002"`) {
		t.Error("findings not by severity")
	}
	in.Findings[1].SetMeta("details", map[string]string{"Location": `<script>x</script>`})
	if x := Report(in); strings.Contains(x, "<script>") {
		t.Fatal("not escaped")
	}
}

// R10: the summary counts the exported findings that have a severity; one
// without is left out of the counts and their total (it stays in the body).
func TestExportSummaryCountsScoredOnly(t *testing.T) {
	high := mk(t, "F-001", "SQL injection", "high", "complete", nil)
	draft := mk(t, "F-002", "Open redirect", "", "draft", nil)
	in := Input{Engagement: store.Engagement{ID: "acme", Name: "ACME Web"}, Findings: []*finding.Finding{high, draft}, Cfg: config.Default()}
	x := Report(in)
	sum := 0
	for _, c := range in.Counts() {
		sum += c.N
	}
	if sum != 1 {
		t.Fatalf("counts sum to %d", sum)
	}
	if !strings.Contains(x, "<tr><th>Findings</th><td>1</td></tr>") {
		t.Fatalf("summary total:\n%s", x)
	}
	if !strings.Contains(x, `data-w="110.0">1 high</span>`) {
		t.Fatalf("the cover bar is not all high:\n%s", x)
	}
	if !strings.Contains(x, `id="rp-F-002"`) {
		t.Fatal("the unscored finding left the report body")
	}
}

// The documents keep the report design (no Field | Value row); the web
// preview, like every web table, has one.
func TestReportKVHeaderOnlyInPreview(t *testing.T) {
	in := input(t)
	if x := Report(in); strings.Contains(x, "<th>Field</th>") {
		t.Fatal("document body has a Field | Value row")
	}
	// R6 (Q9): Confluence pages neither
	for _, macros := range []bool{true, false} {
		if x := XHTML(in, macros); strings.Contains(x, "<th>Field</th>") {
			t.Fatalf("Confluence page (macros %v) has a Field | Value row", macros)
		}
	}
	in.Preview = true
	if x := Report(in); strings.Count(x, kvHead) < 2 {
		t.Fatalf("preview lacks the header:\n%s", x)
	}
}

// D17: in the preview, a finding whose details are all empty shows its
// details table as every empty web table: the header and one "—" row.
func TestReportPreviewEmptyDetails(t *testing.T) {
	in := input(t)
	in.Preview = true
	for _, f := range in.Findings {
		f.SetMeta("details", map[string]string{})
		f.SetMeta("cvss", "")
		f.Meta.Retest = nil // its result is a details row; SetMeta keeps the state
	}
	x := Report(in)
	want := `<table class="rp-details">` + kvHead + `<tbody>` + "\n" + `<tr class="emptyrow"><td colspan="2">—</td></tr>`
	if strings.Count(x, want) != len(in.Findings) {
		t.Fatalf("empty details tables:\n%s", x)
	}
	// D20: no vector shows "—" in the preview, as on the board
	if strings.Count(x, `<td class="num">—</td>`) != len(in.Findings) || strings.Count(x, `<span class="rp-score">—</span>`) != len(in.Findings) {
		t.Fatalf("score without a vector:\n%s", x)
	}
}

func TestHTMLZip(t *testing.T) {
	in := imageInput(t, "http://169.254.169.254/x.png")
	res, err := HTMLZip(in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Filename != "acme-html.zip" || res.ContentType != "application/zip" {
		t.Fatalf("%+v", res.Filename)
	}
	files := unzip(t, res.Data)
	page := files["acme/index.html"]
	if !strings.Contains(page, `<img src="images/F-001-shot.png" alt="shot" />`) || strings.Contains(page, "base64") || strings.Contains(page, "169.254") {
		t.Fatalf("page:\n%s", page)
	}
	if files["acme/images/F-001-shot.png"] != string(pngBytes()) {
		t.Fatalf("files %v", keys(files))
	}
}

func TestFullZip(t *testing.T) {
	repo := t.TempDir()
	os.MkdirAll(filepath.Join(repo, ".git"), 0o755)
	writeFile(t, repo, ".git/HEAD", "ref: refs/heads/main\n", 0o644)
	os.MkdirAll(filepath.Join(repo, "findings", "F-001-x"), 0o755)
	writeFile(t, filepath.Join(repo, "findings", "F-001-x"), "finding.md", "# x", 0o644)
	secret := filepath.Join(t.TempDir(), "secret")
	writeFile(t, filepath.Dir(secret), "secret", "not in the zip", 0o644)
	if err := os.Symlink(secret, filepath.Join(repo, "link")); err != nil {
		t.Fatal(err)
	}
	res, err := FullZip(input(t), repo)
	if err != nil {
		t.Fatal(err)
	}
	files := unzip(t, res.Data)
	if res.Filename != "acme-full.zip" || files["acme/.git/HEAD"] == "" || files["acme/findings/F-001-x/finding.md"] != "# x" || !strings.Contains(files["acme/report.html"], "SQL injection") {
		t.Fatalf("files %v", keys(files))
	}
	if _, ok := files["acme/link"]; ok {
		t.Fatal("symlink followed")
	}
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
