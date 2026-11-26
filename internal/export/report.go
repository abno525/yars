package export

import (
	"archive/zip"
	"bytes"
	"fmt"
	"html"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"yars/internal/cvss"
	"yars/internal/finding"
)

// kvHead heads the two-column label/value tables in the web preview
// (Input.Preview): every web table has a header row.
const kvHead = `<thead><tr><th>Field</th><th>Value</th></tr></thead>`

// SevStyle is a severity's colours in reports (hex, no #).
type SevStyle struct{ BG, FG string }

var sevStyles = map[string]SevStyle{
	"critical": {"7A1010", "FFFFFF"}, "high": {"C4520F", "FFFFFF"}, "medium": {"F6C343", "0F172A"},
	"low": {"9CC3E6", "0F172A"}, "info": {"E6E8EC", "0F172A"},
}

// StyleOf is the report colours of a severity (grey when unknown).
func StyleOf(sev string) SevStyle {
	if s, ok := sevStyles[sev]; ok {
		return s
	}
	return SevStyle{"E6E8EC", "0F172A"}
}

func attr(s string) string { return html.EscapeString(s) }

// sevOf is a finding's severity as the report shows it.
func sevOf(f *finding.Finding) string { return cvss.Derive(f.Meta.CVSS, f.Meta.Severity) }

// sevTag is a severity tag the theme colours (Lua filter, preview CSS).
func sevTag(sev string) string {
	st := StyleOf(sev)
	return `<span class="rp-sev tag sev-` + attr(sev) + `" data-bg="` + st.BG + `" data-fg="` + st.FG + `">` + esc(sev) + `</span>`
}

// Count is how many findings of the report have a severity.
type Count struct {
	Severity string
	N        int
}

// Counts are the report's findings by severity in config order (unknown
// severities last), zeros included.
func (in Input) Counts() []Count {
	var out []Count
	idx := map[string]int{}
	for _, s := range in.Cfg.Severities {
		idx[s] = len(out)
		out = append(out, Count{Severity: s})
	}
	for _, f := range in.Findings {
		s := sevOf(f)
		if s == "" {
			continue
		}
		i, ok := idx[s]
		if !ok {
			i, idx[s] = len(out), len(out)
			out = append(out, Count{Severity: s})
		}
		out[i].N++
	}
	return out
}

// period is the testing dates ("" when unknown).
func (in Input) period() string {
	e := in.Engagement
	return strings.Trim(e.Start+" – "+e.End, " –")
}

// testers are the findings' authors, sorted.
func (in Input) testers() []string {
	var out []string
	for _, f := range in.Findings {
		if a := f.Meta.Author; a != "" && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	slices.Sort(out)
	return out
}

// Report is the report as HTML in the theme's structure: cover, executive
// summary, scope and overview, then each finding with its head (severity
// colour, CVSS), details and sections. The preview shows it; the PDF is
// made from it (the Lua filter turns the marked parts into LaTeX). Every
// value is escaped and finding Markdown has no raw HTML.
func Report(in Input) string {
	var b strings.Builder
	kicker := "Penetration test report"
	if in.Engagement.Type == "retest" {
		kicker = "Retest report"
	}
	counts := in.Counts()
	// the summary counts the findings with a severity (R10): one without is
	// in the body, not in the totals. No draft gets here: a destination takes
	// complete and reported findings only
	total := 0
	for _, c := range counts {
		total += c.N
	}
	b.WriteString(`<div class="rp-cover">` + "\n")
	fmt.Fprintf(&b, `<p><span class="rp-brand">YARS</span> <span class="rp-kicker">%s</span> <span class="rp-title">%s</span> <span class="rp-sub">%s</span></p>`+"\n",
		esc(kicker), esc(in.Engagement.Name), esc(in.subtitle()))
	b.WriteString(`<p class="rp-bar">`)
	for _, c := range counts {
		if c.N == 0 {
			continue
		}
		fmt.Fprintf(&b, `<span class="rp-seg seg-%s" data-color="%s" data-w="%.1f">%d %s</span> `, attr(c.Severity), StyleOf(c.Severity).BG, 110*float64(c.N)/float64(total), c.N, esc(c.Severity))
	}
	b.WriteString("</p>\n")
	b.WriteString(`<p class="rp-meta">`)
	meta := [][2]string{{"Testing", in.period()}, {"Date", time.Now().Format("2006-01-02")}, {"Testers", strings.Join(in.testers(), ", ")}, {"Client", in.Engagement.Client}}
	for _, m := range meta {
		v := m[1]
		if v == "" {
			v = "—"
		}
		fmt.Fprintf(&b, `<span class="rp-m" data-k="%s">%s</span> `, m[0], esc(v))
	}
	b.WriteString("</p>\n</div>\n")

	b.WriteString(`<h1 id="rp-summary">Executive summary</h1>` + "\n")
	for _, rt := range in.Report {
		if out := reportHTML(rt.Body, false); out != "" && isSummary(rt.Name) {
			b.WriteString(out + "\n")
		}
	}
	b.WriteString(`<table class="rp-counts"><thead><tr>`)
	for _, c := range counts {
		b.WriteString("<th>" + sevTag(c.Severity) + "</th>")
	}
	b.WriteString("</tr></thead><tbody><tr>")
	for _, c := range counts {
		fmt.Fprintf(&b, `<td class="num">%d</td>`, c.N)
	}
	b.WriteString("</tr></tbody></table>\n")

	b.WriteString(`<h1 id="rp-scope">Scope and overview</h1>` + "\n")
	// the other report sections (scope, methodology, …) open this chapter
	for _, rt := range in.Report {
		if out := reportHTML(rt.Body, false); out != "" && !isSummary(rt.Name) {
			fmt.Fprintf(&b, "<h2>%s</h2>\n%s\n", esc(rt.Name), out)
		}
	}
	head := ""
	if in.Preview {
		head = kvHead
	}
	b.WriteString(`<table class="rp-kv">` + head + `<tbody>` + "\n")
	kv := [][2]string{{"Engagement", in.Engagement.Name}, {"Client", in.Engagement.Client}, {"Type", in.Engagement.Type}, {"Testing", in.period()}, {"Findings", fmt.Sprint(total)}}
	for _, r := range kv {
		if strings.TrimSpace(r[1]) != "" {
			fmt.Fprintf(&b, "<tr><th>%s</th><td>%s</td></tr>\n", esc(r[0]), esc(r[1]))
		}
	}
	b.WriteString("</tbody></table>\n")
	loc := ""
	if len(in.Cfg.DetailsRows) > 0 {
		loc = in.Cfg.DetailsRows[0]
	}
	b.WriteString(`<table class="rp-overview"><thead><tr><th>ID</th><th>Finding</th><th>Severity</th><th>CVSS</th>`)
	if loc != "" {
		b.WriteString("<th>" + esc(loc) + "</th>")
	}
	b.WriteString("</tr></thead><tbody>\n")
	fs := in.ordered()
	for _, f := range fs {
		m := f.Meta
		fmt.Fprintf(&b, `<tr><td class="fid">%s</td><td>%s</td><td>%s</td><td class="num">%s</td>`, esc(m.ID), esc(m.Title), sevTag(sevOf(f)), esc(scoreOf(f, in.Preview)))
		if loc != "" {
			b.WriteString("<td>" + esc(m.Details[loc]) + "</td>")
		}
		b.WriteString("</tr>\n")
	}
	b.WriteString("</tbody></table>\n")

	b.WriteString(`<h1 id="rp-findings">Findings</h1>` + "\n")
	for _, f := range fs {
		m := f.Meta
		sev := sevOf(f)
		st := StyleOf(sev)
		vec := ""
		if v, err := cvss.Parse(m.CVSS); err == nil {
			vec = v.String()
		}
		fmt.Fprintf(&b, `<div class="rp-fhead sevbar-%s" id="rp-%s" data-bg="%s" data-fg="%s" data-sev="%s">`+"\n", attr(sev), attr(m.ID), st.BG, st.FG, attr(sev))
		fmt.Fprintf(&b, `<p><span class="rp-fid">%s</span> <span class="rp-ftitle">%s</span> %s <span class="rp-vec">%s</span> <span class="rp-score">%s</span></p>`+"\n</div>\n",
			esc(m.ID), esc(m.Title), sevTag(sev), esc(vec), esc(scoreOf(f, in.Preview)))
		b.WriteString(`<table class="rp-details">` + head + `<tbody>` + "\n")
		rows := 0
		for _, r := range summary(f, in.Cfg)[1:] { // severity is in the head
			if r.Label == "CVSS" {
				continue
			}
			fmt.Fprintf(&b, "<tr><th>%s</th><td>%s</td></tr>\n", esc(r.Label), esc(r.Value))
			rows++
		}
		if rows == 0 && in.Preview {
			// as every empty web table (D17)
			b.WriteString(`<tr class="emptyrow"><td colspan="2">—</td></tr>` + "\n")
		}
		b.WriteString("</tbody></table>\n")
		if rs := reasons(f, in.Cfg); len(rs) > 0 {
			b.WriteString(`<table class="rp-reasons"><thead><tr><th>Metric</th><th>Value</th><th>Explanation</th></tr></thead><tbody>` + "\n")
			for _, r := range rs {
				fmt.Fprintf(&b, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", esc(r[0]), esc(r[1]), esc(r[2]))
			}
			b.WriteString("</tbody></table>\n")
		}
		writeSections(&b, f, in, false)
	}
	return b.String()
}

// scoreOf is the CVSS base score; without a vector "–" in the documents,
// "—" in the web preview as everywhere on the web (D20).
func scoreOf(f *finding.Finding, preview bool) string {
	v, err := cvss.Parse(f.Meta.CVSS)
	if err != nil {
		if preview {
			return "—"
		}
		return "–"
	}
	sc, _ := cvss.Score(v)
	return cvss.FormatScore(sc)
}

// HTMLZip is the report as a Confluence-importable ZIP: <eng>/index.html
// with the attachments the findings show in <eng>/images/.
func HTMLZip(in Input) (Result, error) {
	type img struct {
		name string
		data []byte
	}
	var imgs []img
	used := map[string]bool{}
	in.imageSrc = func(f *finding.Finding, rel, ct string, data []byte) string {
		name := f.Meta.ID + "-" + path.Base(rel)
		if !used[name] {
			used[name] = true
			imgs = append(imgs, img{name, data})
		}
		return "images/" + name
	}
	doc := "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\" /><title>" + esc(in.Engagement.Name) + "</title></head><body>\n<h1>" +
		esc(in.Engagement.Name) + "</h1>\n<p>" + esc(in.subtitle()) + "</p>\n" + XHTML(in, false) + "</body></html>\n"
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name string, data []byte) error {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: time.Now()})
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	root := in.Engagement.ID + "/"
	if err := add(root+"index.html", []byte(doc)); err != nil {
		return Result{}, err
	}
	for _, im := range imgs {
		if err := add(root+"images/"+im.name, im.data); err != nil {
			return Result{}, err
		}
	}
	if err := zw.Close(); err != nil {
		return Result{}, err
	}
	return Result{Filename: in.Engagement.ID + "-html.zip", ContentType: "application/zip", Data: buf.Bytes()}, nil
}

// FullZip is everything of the engagement: its git repository (work tree
// and .git, plain files only) and the report as HTML, under <eng>/.
func FullZip(in Input, repoDir string) (Result, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	root := in.Engagement.ID + "/"
	err := filepath.WalkDir(repoDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(repoDir, p)
		if err != nil || rel == "." {
			return err
		}
		// only plain files: links could point out of the repository
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		h, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		h.Name, h.Method = root+filepath.ToSlash(rel), zip.Deflate
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		if _, err := io.Copy(w, src); err != nil {
			return err
		}
		if buf.Len() > maxOutput {
			return fmt.Errorf("full export larger than %d MB", maxOutput>>20)
		}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	doc := "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\" /><title>" + esc(in.Engagement.Name) + "</title></head><body>\n" + Report(in) + "</body></html>\n"
	w, err := zw.CreateHeader(&zip.FileHeader{Name: root + "report.html", Method: zip.Deflate, Modified: time.Now()})
	if err != nil {
		return Result{}, err
	}
	w.Write([]byte(doc))
	if err := zw.Close(); err != nil {
		return Result{}, err
	}
	return Result{Filename: in.Engagement.ID + "-full.zip", ContentType: "application/zip", Data: buf.Bytes()}, nil
}
