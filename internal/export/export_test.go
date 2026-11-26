package export

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/store"
)

func mk(t *testing.T, id, title, sev, status string, sections map[string]string) *finding.Finding {
	t.Helper()
	f := finding.New(id, title, "alice", []string{"Description", "Impact"})
	f.SetMeta("severity", sev)
	f.SetMeta("status", status)
	for k, v := range sections {
		f.SetSection(k, v)
	}
	return f
}

func input(t *testing.T) Input {
	t.Helper()
	low := mk(t, "F-002", "Missing HSTS", "low", "complete", map[string]string{"Impact": "Downgrade."})
	high := mk(t, "F-001", "SQL injection", "high", "complete", map[string]string{"Description": "Login form.\n\n### Detail\n\n```\nid=1'\n```", "Impact": "DB read | all rows."})
	high.SetMeta("cvss", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N")
	high.SetMeta("cvss_reasons", map[string]string{"AC": "race with refresh"})
	high.SetMeta("details", finding.OrderedMap([]string{"Location", "Business impact"}, map[string]string{"Location": "https://x/login\nparam user", "Business impact": "Account takeover"}))
	rt := mk(t, "F-003", "XSS", "medium", "complete", nil)
	rt.Meta.Retest = &finding.Retest{Source: "old/F-003-xss", Result: "not_fixed"} // state, filled from the database
	return Input{Engagement: store.Engagement{ID: "acme", Name: "ACME Web", Client: "ACME"}, Findings: []*finding.Finding{low, high, rt}, Cfg: config.Default()}
}

func writeFile(t *testing.T, dir, name, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "docx.yaml", "name: DOCX\ntype: pandoc\nformat: docx\n", 0o644)
	writeFile(t, dir, "conf.yaml", "name: Confluence\ntype: confluence\n", 0o644)
	writeFile(t, dir, "bad.yaml", "name: Bad\ntype: word\n", 0o644)
	writeFile(t, dir, "typo.yaml", "name: Typo\ntype: pandoc\nformat: docx\nfromat: x\n", 0o644)
	es, errs := Load(dir)
	if len(es) != 2 || es[0].ID != "conf" || es[1].ID != "docx" || es[1].Name != "DOCX" {
		t.Fatalf("exporters %+v", es)
	}
	all := ""
	for _, e := range errs {
		all += e.Error() + "\n"
	}
	if !strings.Contains(all, "bad.yaml") || !strings.Contains(all, "typo.yaml") {
		t.Fatalf("errors:\n%s", all)
	}
	if !es[1].Marks() || len(es[1].Statuses) != 1 || es[1].Statuses[0] != "complete" {
		t.Fatalf("defaults %+v", es[1])
	}
}

// An exporter selects only finished findings by status (R10): withdrawn,
// draft and in-review ones never.
func TestLoadDropsWithdrawnStatus(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "all.yaml", "name: All\ntype: pandoc\nformat: docx\nstatuses: [complete, withdrawn, draft, verification, approval, reported]\n", 0o644)
	writeFile(t, dir, "only.yaml", "name: Only\ntype: pandoc\nformat: docx\nstatuses: [withdrawn, draft]\n", 0o644)
	es, errs := Load(dir)
	if len(errs) != 0 || len(es) != 2 {
		t.Fatalf("%+v %v", es, errs)
	}
	if got := strings.Join(es[0].Statuses, ","); got != "complete,reported" {
		t.Fatalf("all: %q", got)
	}
	if got := strings.Join(es[1].Statuses, ","); got != "complete" {
		t.Fatalf("only: %q", got)
	}
}

func TestXHTMLLayout(t *testing.T) {
	x := XHTML(input(t), false)
	i1, i2, i3 := strings.Index(x, "<h1>F-001 SQL injection</h1>"), strings.Index(x, "<h1>F-003 XSS</h1>"), strings.Index(x, "<h1>F-002 Missing HSTS</h1>")
	if i1 < 0 || !(i1 < i2 && i2 < i3) {
		t.Fatalf("order/headings:\n%s", x)
	}
	for _, want := range []string{
		"<tr><th>Severity</th><td>high</td></tr>",
		"<tr><th>CVSS</th><td>7.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)</td></tr>",
		"<tr><th>Location</th><td>https://x/login<br />param user</td></tr>",
		"<tr><td>Attack Complexity</td><td>High</td><td>race with refresh</td></tr>",
		"<tr><th>Retest result</th><td>Not fixed</td></tr>",
		"<h2>Description</h2>",
		"<h3>Detail</h3>",
		"DB read | all rows.",
	} {
		if !strings.Contains(x, want) {
			t.Errorf("missing %q in:\n%s", want, x)
		}
	}
}

// A heading written in a finding's body (#, ##, or underlined) sits below
// the finding's title (h1) and its section (h2) in every export: it is an
// h3 at most; ### and lower keep their level (backlog, M8).
func TestBodyHeadingsBelowSections(t *testing.T) {
	in := input(t)
	in.Findings[0].SetSection("Description", "# Big\n\n## Medium\n\nUnderlined\n==========\n\n### Small\n\n#### Smaller\n\ntext")
	in.Report = append(in.Report, ReportText{Name: "Scope", Body: "# Hosts\n\nall"})
	// Jira's wiki markup too (review)
	if j := mdToJira("# Big\n\n## Medium\n\n### Small\n\n#### Smaller"); !strings.Contains(j, "h3. Big") || !strings.Contains(j, "h3. Medium") || !strings.Contains(j, "h4. Smaller") || strings.Contains(j, "h1.") || strings.Contains(j, "h2.") {
		t.Errorf("jira:\n%s", j)
	}
	for name, x := range map[string]string{"xhtml": XHTML(in, false), "report": Report(in)} {
		for _, want := range []string{"<h3>Big</h3>", "<h3>Medium</h3>", "<h3>Underlined</h3>", "<h3>Small</h3>", "<h4>Smaller</h4>", "<h3>Hosts</h3>"} {
			if !strings.Contains(x, want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
		for _, bad := range []string{"<h1>Big", "<h2>Medium", "<h1>Underlined", "<h1>Hosts"} {
			if strings.Contains(x, bad) {
				t.Errorf("%s has %q", name, bad)
			}
		}
	}
}

func pngBytes() []byte {
	return []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xa7\x35\x81\x84\x00\x00\x00\x00IEND\xaeB`\x82")
}

// imageInput has one finding with a local-file image, a remote image and a
// legitimate attachment.
func imageInput(t *testing.T, remote string) Input {
	in := input(t)
	in.Findings[1].SetSection("Impact", "![leak](/etc/hostname)\n\n![ssrf]("+remote+")\n\n![shot](attachments/shot.png)")
	in.Attachment = func(f *finding.Finding, rel string) ([]byte, bool) {
		if f.Meta.ID == "F-001" && rel == "attachments/shot.png" {
			return pngBytes(), true
		}
		return nil, false
	}
	return in
}

func TestXHTMLImages(t *testing.T) {
	x := XHTML(imageInput(t, "http://169.254.169.254/x.png"), false)
	if strings.Contains(x, "/etc/hostname\"") || strings.Contains(x, "169.254.169.254") {
		t.Fatalf("foreign image kept:\n%s", x)
	}
	if !strings.Contains(x, `src="data:image/png;base64,`) || strings.Count(x, "image removed") != 2 {
		t.Fatalf("attachment not inlined / others not removed:\n%s", x)
	}
}

func TestPandocSandboxImages(t *testing.T) {
	p, err := exec.LookPath("pandoc")
	if err != nil {
		t.Skip("pandoc not installed")
	}
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++; w.Write(pngBytes()) }))
	defer srv.Close()
	r, _ := runner(t, p)
	res, err := r.Run(context.Background(), Exporter{ID: "docx", Type: "pandoc", Format: "docx"}, imageInput(t, srv.URL+"/x.png"))
	if err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatalf("pandoc fetched a remote image (%d hits)", hits)
	}
	zr, err := zip.NewReader(bytes.NewReader(res.Data), int64(len(res.Data)))
	if err != nil {
		t.Fatal(err)
	}
	media := 0
	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "word/media/") {
			media++
		}
	}
	if media != 1 {
		t.Fatalf("want exactly the attachment embedded, got %d media files", media)
	}
}

func TestLoadValidatesConfig(t *testing.T) {
	bad := map[string]string{
		"lua.yaml":   "type: pandoc\nformat: docx\nargs: [--lua-filter=/tmp/x.lua]\n",
		"out.yaml":   "type: pandoc\nformat: docx\nargs: [-o, /tmp/x]\n",
		"env.yaml":   "type: confluence\nconfluence: {base_url: https://x, space: S, user_env: CONFLUENCE_USER, token_env: YARS_AI_KEY}\n",
		"ext.yaml":   "type: script\nscript: s.sh\nextension: ../../x\n",
		"space.yaml": "type: confluence\nconfluence: {base_url: https://x, user_env: CONFLUENCE_USER, token_env: CONFLUENCE_TOKEN}\n",
	}
	dir := t.TempDir()
	for n, b := range bad {
		writeFile(t, dir, n, b, 0o644)
	}
	writeFile(t, dir, "ok.yaml", "type: pandoc\nformat: docx\nargs: [--toc, --toc-depth=2, --number-sections]\n", 0o644)
	es, errs := Load(dir)
	if len(es) != 1 || es[0].ID != "ok" || len(errs) != len(bad) {
		t.Fatalf("exporters %v errors %v", es, errs)
	}
}

// fakePandoc records its args and stdin, then writes stdin to -o.
func fakePandoc(t *testing.T, body string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "pandoc")
	writeFile(t, dir, "pandoc", "#!/bin/sh\n"+body, 0o755)
	return p, dir
}

// waitFor waits up to 10 s for cond, so a slow machine only makes a test
// slower.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("gave up waiting")
		}
	}
}

const recordingPandoc = `printf '%s\n' "$@" > "$(dirname "$0")/args.txt"
out=""
while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then out="$2"; fi; shift; done
cat > "$out"
`

func runner(t *testing.T, pandoc string) (*Runner, string) {
	t.Helper()
	dir := t.TempDir()
	return &Runner{Dir: dir, PandocPath: pandoc, HTTP: &http.Client{}, Getenv: func(string) string { return "" }, Timeout: 5 * time.Second}, dir
}

func TestPandocRun(t *testing.T) {
	pb, pdir := fakePandoc(t, recordingPandoc)
	r, edir := runner(t, pb)
	writeFile(t, edir, "ref.docx", "template", 0o644)
	res, err := r.Run(context.Background(), Exporter{ID: "docx", Name: "D", Type: "pandoc", Format: "docx", Template: "ref.docx", Args: []string{"--toc"}}, input(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Filename != "acme.docx" || !bytes.Contains(res.Data, []byte("<h1>F-001 SQL injection</h1>")) {
		t.Fatalf("result %s %q", res.Filename, res.Data[:min(len(res.Data), 80)])
	}
	args, _ := os.ReadFile(filepath.Join(pdir, "args.txt"))
	for _, want := range []string{"-f\nhtml", "-t\ndocx", "--reference-doc=" + filepath.Join(edir, "ref.docx"), "--toc", "title=ACME Web"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("args lack %q:\n%s", want, args)
		}
	}
}

// A pandoc format with extensions (docx+styles, markdown-smart) is a
// format: it goes to pandoc whole, and the base format picks the file
// extension and the reference document (backlog, M8).
func TestPandocFormatExtensions(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "styled.yaml", "type: pandoc\nformat: docx+styles\ntemplate: ref.docx\n", 0o644)
	writeFile(t, dir, "md.yaml", "type: pandoc\nformat: markdown-smart+pipe_tables\n", 0o644)
	writeFile(t, dir, "bad.yaml", "type: pandoc\nformat: docx+\n", 0o644)
	if es, errs := Load(dir); len(es) != 2 || len(errs) != 1 {
		t.Fatalf("exporters %v errors %v", es, errs)
	}
	pb, pdir := fakePandoc(t, recordingPandoc)
	r, edir := runner(t, pb)
	writeFile(t, edir, "ref.docx", "template", 0o644)
	res, err := r.Run(context.Background(), Exporter{ID: "styled", Type: "pandoc", Format: "docx+styles", Template: "ref.docx"}, input(t))
	if err != nil || res.Filename != "acme.docx" {
		t.Fatalf("%v %s", err, res.Filename)
	}
	args, _ := os.ReadFile(filepath.Join(pdir, "args.txt"))
	for _, want := range []string{"-t\ndocx+styles", "--reference-doc=" + filepath.Join(edir, "ref.docx")} {
		if !strings.Contains(string(args), want) {
			t.Errorf("args lack %q:\n%s", want, args)
		}
	}
	if res, err := r.Run(context.Background(), Exporter{ID: "md", Type: "pandoc", Format: "markdown-smart+pipe_tables"}, input(t)); err != nil || res.Filename != "acme.md" {
		t.Fatalf("%v %s", err, res.Filename)
	}
}

// An export whose request went away (the browser closed) says it was
// cancelled; only a run that reached its time limit says it timed out
// (backlog, M8).
func TestExportCancelledIsNotTimeout(t *testing.T) {
	pb, _ := fakePandoc(t, "exec sleep 5\n")
	r, edir := runner(t, pb)
	writeFile(t, edir, "slow.sh", "#!/bin/sh\nexec sleep 5\n", 0o755)
	for _, ex := range []Exporter{{ID: "d", Type: "pandoc", Format: "docx"}, {ID: "s", Type: "script", Script: "slow.sh", Extension: "txt"}} {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(200*time.Millisecond, cancel)
		if _, err := r.Run(ctx, ex, input(t)); err == nil || !strings.Contains(err.Error(), "cancelled") || strings.Contains(err.Error(), "timed out") {
			t.Errorf("%s cancelled: %v", ex.Type, err)
		}
		ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
		if _, err := r.Run(ctx, ex, input(t)); err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Errorf("%s deadline: %v", ex.Type, err)
		}
		cancel()
	}
}

// A download's type comes from YARS, not from the server's mime table
// (which may lack docx, odt, epub, md): the browser opens the right program
// (backlog, M8).
func TestPandocContentTypes(t *testing.T) {
	pb, _ := fakePandoc(t, recordingPandoc)
	r, _ := runner(t, pb)
	for format, want := range map[string]string{
		"docx":     "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"odt":      "application/vnd.oasis.opendocument.text",
		"pptx":     "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"epub":     "application/epub+zip",
		"rtf":      "application/rtf",
		"markdown": "text/markdown; charset=utf-8",
		"html":     "text/html; charset=utf-8",
		"plain":    "text/plain; charset=utf-8",
		"latex":    "application/x-tex",
	} {
		res, err := r.Run(context.Background(), Exporter{ID: format, Type: "pandoc", Format: format}, input(t))
		if err != nil || res.ContentType != want {
			t.Errorf("%s: %q %v", format, res.ContentType, err)
		}
	}
	// a script's result too, by its extension
	writeFile(t, r.Dir, "md.sh", "#!/bin/sh\necho '# Report'\n", 0o755)
	if res, err := r.Run(context.Background(), Exporter{ID: "s", Type: "script", Script: "md.sh", Extension: "md"}, input(t)); err != nil || res.ContentType != "text/markdown; charset=utf-8" {
		t.Errorf("script: %q %v", res.ContentType, err)
	}
}

// At most four exports run at once (each may hold up to 100 MB): a fifth
// waits for a slot, and gives up when its request does (backlog, M8).
func TestExportWorkers(t *testing.T) {
	pb, _ := fakePandoc(t, "exec sleep 5\n")
	r, _ := runner(t, pb)
	busy, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for range exportWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Run(busy, Exporter{ID: "d", Type: "pandoc", Format: "docx"}, input(t))
		}()
	}
	waitFor(t, func() bool { return len(r.runQueue()) == exportWorkers })
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := r.Run(ctx, Exporter{ID: "c", Type: "confluence"}, input(t)); err == nil || err.Error() != "export not started: timed out" {
		t.Fatalf("a fifth export: %v", err)
	}
	gone, leave := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, leave)
	if _, err := r.Run(gone, Exporter{ID: "c", Type: "confluence"}, input(t)); err == nil || err.Error() != "export not started: cancelled" {
		t.Fatalf("a fifth export whose request went away: %v", err)
	}
	stop()
	wg.Wait()
	if res, err := r.Run(context.Background(), Exporter{ID: "c", Type: "confluence"}, input(t)); err != nil || res.Filename == "" {
		t.Fatalf("after the others: %v", err)
	}
}

// A pandoc that floods its error output past the 1 MiB cap is stopped at
// once (the pipe is closed on it), not left blocked until the timeout
// (backlog, M8: kept as a test, M34 review).
func TestPandocStderrFloodStops(t *testing.T) {
	pb, _ := fakePandoc(t, "exec head -c 16000000 /dev/zero >&2\n")
	r, _ := runner(t, pb)
	start := time.Now()
	_, err := r.Run(context.Background(), Exporter{ID: "d", Type: "pandoc", Format: "docx"}, input(t))
	if err == nil || strings.Contains(err.Error(), "timed out") || time.Since(start) > 3*time.Second {
		t.Fatalf("%v after %s", err, time.Since(start))
	}
}

func TestPandocReal(t *testing.T) {
	p, err := exec.LookPath("pandoc")
	if err != nil {
		t.Skip("pandoc not installed")
	}
	r, _ := runner(t, p)
	res, err := r.Run(context.Background(), Exporter{ID: "docx", Type: "pandoc", Format: "docx"}, input(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(res.Data, []byte("PK")) {
		t.Fatal("not a docx (zip)")
	}
	// multi-line details keep their line break in the document
	docx := filepath.Join(t.TempDir(), "r.docx")
	os.WriteFile(docx, res.Data, 0o644)
	txt, err := exec.Command(p, "-t", "plain", docx).Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(txt), "loginparam") || !strings.Contains(string(txt), "param user") || !strings.Contains(string(txt), "id=1'") {
		t.Fatalf("content:\n%s", txt)
	}
}

func TestPandocFailure(t *testing.T) {
	pb, _ := fakePandoc(t, "echo 'Unknown output format' >&2\nexit 1\n")
	r, _ := runner(t, pb)
	if _, err := r.Run(context.Background(), Exporter{ID: "x", Type: "pandoc", Format: "nope"}, input(t)); err == nil || !strings.Contains(err.Error(), "Unknown output format") {
		t.Fatalf("err %v", err)
	}
	pb, _ = fakePandoc(t, "sleep 5\n")
	r, _ = runner(t, pb)
	r.Timeout = 300 * time.Millisecond
	start := time.Now()
	if _, err := r.Run(context.Background(), Exporter{ID: "x", Type: "pandoc", Format: "docx"}, input(t)); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("hang: err %v after %s", err, time.Since(start))
	}
	r.PandocPath = ""
	if _, err := r.Run(context.Background(), Exporter{ID: "x", Type: "pandoc", Format: "docx"}, input(t)); err == nil || !strings.Contains(err.Error(), "pandoc") {
		t.Fatalf("missing pandoc: %v", err)
	}
}

func TestConfluenceEscapes(t *testing.T) {
	in := input(t)
	in.Findings[1].SetSection("Impact", `<ac:structured-macro ac:name="html"><ac:plain-text-body>x</ac:plain-text-body></ac:structured-macro> and <script>alert(1)</script>`)
	in.Findings[1].SetMeta("details", map[string]string{"Location": `<b onmouseover="x">loc</b>`})
	for _, macros := range []bool{false, true} {
		x := XHTML(in, macros)
		if strings.Contains(x, "<ac:structured-macro ac:name=\"html\"") || strings.Contains(x, "<script>") || strings.Contains(x, "<b onmouseover") {
			t.Fatalf("injection (macros=%v):\n%s", macros, x)
		}
		if !strings.Contains(x, "&lt;b onmouseover") {
			t.Fatalf("details not escaped (macros=%v)", macros)
		}
	}
	x := XHTML(input(t), true)
	if !strings.Contains(x, `<ac:structured-macro ac:name="code">`) || !strings.Contains(x, "<![CDATA[id=1'") {
		t.Fatalf("no code macro:\n%s", x)
	}
	if strings.Contains(XHTML(input(t), false), "ac:structured-macro") {
		t.Fatal("macros in download mode")
	}
}

func TestConfluenceDownload(t *testing.T) {
	r, _ := runner(t, "")
	res, err := r.Run(context.Background(), Exporter{ID: "c", Type: "confluence"}, input(t))
	if err != nil || res.Filename != "acme.html" || !strings.HasPrefix(res.ContentType, "text/html") || !bytes.Contains(res.Data, []byte("SQL injection")) {
		t.Fatalf("%v %+v", err, res.Filename)
	}
}

func TestConfluencePush(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if r.URL.Path != "/wiki/rest/api/content" || !ok || u != "bot@acme" || p != "tok123" {
			w.WriteHeader(401)
			return
		}
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		io.WriteString(w, `{"id":"99","_links":{"base":"https://acme.atlassian.net/wiki","webui":"/spaces/SEC/pages/99"}}`)
	}))
	defer srv.Close()
	r, _ := runner(t, "")
	r.Getenv = func(k string) string { return map[string]string{"CU": "bot@acme", "CT": "tok123"}[k] }
	e := Exporter{ID: "c", Type: "confluence", Confluence: &ConfluenceConf{BaseURL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/wiki", Space: "SEC", ParentID: "12", UserEnv: "CU", TokenEnv: "CT"}}
	res, err := r.Run(context.Background(), e, input(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.URL != "https://acme.atlassian.net/wiki/spaces/SEC/pages/99" {
		t.Fatalf("url %q", res.URL)
	}
	body, _ := json.Marshal(got)
	if !strings.Contains(string(body), "SQL injection") || !strings.Contains(string(body), `"key":"SEC"`) || !strings.Contains(string(body), `"id":"12"`) {
		t.Fatalf("payload %s", body)
	}
}

// Pasted terminal output carries control characters (ANSI colours), which
// XML forbids: the page sent to Confluence drops them, so it is accepted,
// and keeps the text around them (backlog, M8).
func TestConfluenceDropsControlCharacters(t *testing.T) {
	var storage string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got struct {
			Body struct {
				Storage struct{ Value string } `json:"storage"`
			} `json:"body"`
		}
		json.NewDecoder(r.Body).Decode(&got)
		storage = got.Body.Storage.Value
		io.WriteString(w, `{"id":"99","_links":{"base":"https://acme.atlassian.net/wiki","webui":"/pages/99"}}`)
	}))
	defer srv.Close()
	in := input(t)
	in.Findings[0].SetSection("Impact", "Output: \x1b[31mred\x1b[0m, a bell \x07 and a tab\there.\n\n```\n\x1b[1mbold\x1b[0m\n```")
	r, _ := runner(t, "")
	r.Getenv = func(k string) string { return "x" }
	e := Exporter{ID: "c", Type: "confluence", Confluence: &ConfluenceConf{BaseURL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/wiki", Space: "SEC", UserEnv: "CU", TokenEnv: "CT"}}
	if _, err := r.Run(context.Background(), e, in); err != nil {
		t.Fatal(err)
	}
	for _, c := range storage {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			t.Fatalf("control character %U in the page:\n%q", c, storage)
		}
	}
	if !strings.Contains(storage, "[31mred[0m, a bell  and a tab\there.") || !strings.Contains(storage, "[1mbold[0m") {
		t.Fatalf("text lost:\n%q", storage)
	}
}

// Task lists reach Confluence as ☐ and ☑ text: storage format has no
// <input>, so a page with one may be refused. The other exports keep the
// checkboxes for pandoc and the browser (backlog, M8).
func TestConfluenceTaskList(t *testing.T) {
	in := input(t)
	in.Findings[0].SetSection("Impact", "- [ ] rotate keys\n- [x] patch")
	push := XHTML(in, true)
	if strings.Contains(push, "<input") || !strings.Contains(push, "☐ rotate keys") || !strings.Contains(push, "☑ patch") {
		t.Fatalf("push:\n%s", push)
	}
	if !strings.Contains(XHTML(in, false), `type="checkbox"`) {
		t.Fatal("the download lost its checkboxes")
	}
}

func TestConfluenceRepublish(t *testing.T) {
	var method, path string
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			io.WriteString(w, `{"results":[{"id":"99","version":{"number":3}}]}`)
			return
		}
		method, path = r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &got)
		io.WriteString(w, `{"id":"99","_links":{"base":"https://w","webui":"/p/99"}}`)
	}))
	defer srv.Close()
	r, _ := runner(t, "")
	r.Getenv = func(k string) string { return map[string]string{"CONFLUENCE_U": "u", "CONFLUENCE_T": "t"}[k] }
	e := Exporter{ID: "c", Type: "confluence", Confluence: &ConfluenceConf{BaseURL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), Space: "S", UserEnv: "CONFLUENCE_U", TokenEnv: "CONFLUENCE_T"}}
	res, err := r.Run(context.Background(), e, input(t))
	if err != nil || res.URL != "https://w/p/99" || !res.Pushed {
		t.Fatalf("%v %+v", err, res)
	}
	if method != "PUT" || path != "/rest/api/content/99" || got["version"].(map[string]any)["number"].(float64) != 4 {
		t.Fatalf("update: %s %s %v", method, path, got["version"])
	}
}

func TestConfluencePushErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			io.WriteString(w, `{"results":[]}`)
			return
		}
		w.WriteHeader(400)
		io.WriteString(w, `{"message":"bad token tok123 for bot"}`)
	}))
	defer srv.Close()
	r, _ := runner(t, "")
	r.Getenv = func(k string) string { return map[string]string{"CU": "bot", "CT": "tok123"}[k] }
	e := Exporter{ID: "c", Type: "confluence", Confluence: &ConfluenceConf{BaseURL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), Space: "S", UserEnv: "CU", TokenEnv: "CT"}}
	_, err := r.Run(context.Background(), e, input(t))
	if err == nil || strings.Contains(err.Error(), "tok123") || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "bad token") {
		t.Fatalf("err %v", err)
	}
	e.Confluence.BaseURL = "http://evil.example/wiki"
	if _, err := r.Run(context.Background(), e, input(t)); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http accepted: %v", err)
	}
}

// Templates and scripts outside the exporters folder are refused as such,
// though the files exist: by a relative path, an absolute one and a
// symlink (backlog, M8: the test used /etc/hostname and missing files).
func TestExporterPathEscape(t *testing.T) {
	pb, _ := fakePandoc(t, recordingPandoc)
	r, edir := runner(t, pb)
	outside := filepath.Join(t.TempDir(), "secret.docx")
	writeFile(t, filepath.Dir(outside), "secret.docx", "x", 0o644)
	writeFile(t, filepath.Dir(edir), "x.docx", "x", 0o644)
	writeFile(t, filepath.Dir(edir), "s.sh", "#!/bin/sh\necho hi\n", 0o755)
	if err := os.Symlink(outside, filepath.Join(edir, "link.docx")); err != nil {
		t.Fatal(err)
	}
	for _, tpl := range []string{"../x.docx", outside, "link.docx"} {
		if _, err := r.Run(context.Background(), Exporter{ID: "x", Type: "pandoc", Format: "docx", Template: tpl}, input(t)); err == nil || !strings.Contains(err.Error(), "outside") {
			t.Errorf("%s: %v", tpl, err)
		}
	}
	if _, err := r.Run(context.Background(), Exporter{ID: "s", Type: "script", Script: "../s.sh", Extension: "txt"}, input(t)); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Errorf("script escape: %v", err)
	}
}

// A missing file whose name starts with two dots (..notes.docx) is inside
// the folder: its error is "not found", not "outside" (backlog, M8).
func TestExporterDotDotName(t *testing.T) {
	r, _ := runner(t, "")
	_, err := r.safePath("..notes.docx")
	if err == nil || strings.Contains(err.Error(), "outside") || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err %v", err)
	}
}

func TestScriptExporter(t *testing.T) {
	r, edir := runner(t, "")
	writeFile(t, edir, "count.sh", "#!/bin/sh\ngrep -o '\"id\":\"F-' | wc -l\n", 0o755)
	res, err := r.Run(context.Background(), Exporter{ID: "count", Type: "script", Script: "count.sh", Extension: "txt"}, input(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Filename != "acme.txt" || strings.TrimSpace(string(res.Data)) != "3" {
		t.Fatalf("%s %q", res.Filename, res.Data)
	}
}

// The script exporter gets the engagement with lowercase keys and each
// finding's retest result and attachments.
func TestScriptExporterKeys(t *testing.T) {
	r, edir := runner(t, "")
	out := filepath.Join(t.TempDir(), "in.json")
	writeFile(t, edir, "dump.sh", "#!/bin/sh\ncat > "+out+"\necho ok\n", 0o755)
	in := input(t)
	in.Engagement.Start, in.Engagement.End = "2026-11-04", "2026-11-07"
	in.Findings[1].SetSection("Impact", "![s](attachments/shot.png)")
	if _, err := r.Run(context.Background(), Exporter{ID: "d", Type: "script", Script: "dump.sh", Extension: "txt"}, in); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(out)
	var got struct {
		Engagement map[string]any `json:"engagement"`
		Findings   []map[string]any
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	e := got.Engagement
	if e["id"] != "acme" || e["name"] != "ACME Web" || e["client"] != "ACME" || e["start"] != "2026-11-04" || e["Name"] != nil {
		t.Fatalf("engagement %v", e)
	}
	var xss, sqli map[string]any
	for _, f := range got.Findings {
		switch f["id"] {
		case "F-003":
			xss = f
		case "F-001":
			sqli = f
		}
	}
	if xss["retest_result"] != "not_fixed" {
		t.Fatalf("retest %v", xss)
	}
	if a, _ := sqli["attachments"].([]any); len(a) != 1 || a[0] != "shot.png" {
		t.Fatalf("attachments %v", sqli["attachments"])
	}
}

func TestLoadJira(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "jira.yaml", "name: Jira\ntype: jira\nmark_reported: false\njira: {base_url: https://jira.acme.com, project: PEN, user_env: JIRA_USER, token_env: JIRA_TOKEN}\n", 0o644)
	writeFile(t, dir, "noproj.yaml", "type: jira\njira: {base_url: https://jira.acme.com, user_env: JIRA_USER, token_env: JIRA_TOKEN}\n", 0o644)
	writeFile(t, dir, "nojira.yaml", "type: jira\n", 0o644)
	writeFile(t, dir, "env.yaml", "type: jira\njira: {base_url: https://j, project: P, user_env: JIRA_USER, token_env: YARS_AI_KEY}\n", 0o644)
	es, errs := Load(dir)
	if len(es) != 1 || es[0].ID != "jira" || len(errs) != 3 {
		t.Fatalf("exporters %+v errors %v", es, errs)
	}
	if es[0].Jira.IssueType != "Bug" || es[0].Marks() || !es[0].Service() {
		t.Fatalf("defaults %+v", es[0].Jira)
	}
	if (Exporter{Type: "confluence"}).Service() || !(Exporter{Type: "confluence", Confluence: &ConfluenceConf{BaseURL: "https://x"}}).Service() {
		t.Fatal("confluence service")
	}
}

// Jira gets one issue per finding with the severity as priority; the
// sender's key wins over the server's.
func TestJiraExporter(t *testing.T) {
	var mu sync.Mutex
	var got []map[string]any
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "pen1@acme" || p != "own" {
			w.WriteHeader(401)
			io.WriteString(w, `{"errorMessages":["bad key own"]}`)
			return
		}
		if r.Method == "GET" && r.URL.Path == "/rest/api/2/search" {
			io.WriteString(w, `{"issues":[]}`)
			return
		}
		if r.Method != "POST" || r.URL.Path != "/rest/api/2/issue" {
			w.WriteHeader(400)
			return
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		got = append(got, body)
		n++
		k := n
		mu.Unlock()
		w.WriteHeader(201)
		io.WriteString(w, `{"id":"1000`+string(rune('0'+k))+`","key":"PEN-`+string(rune('0'+k))+`"}`)
	}))
	defer srv.Close()
	r, _ := runner(t, "")
	r.Getenv = func(k string) string { return map[string]string{"JIRA_USER": "bot", "JIRA_TOKEN": "server"}[k] }
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	e := Exporter{ID: "j", Type: "jira", Jira: &JiraConf{BaseURL: base, Project: "PEN", IssueType: "Bug", UserEnv: "JIRA_USER", TokenEnv: "JIRA_TOKEN"}}
	in := input(t)
	in.Creds = &Creds{User: "pen1@acme", Token: "own"}
	res, err := r.Run(context.Background(), e, in)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Pushed || len(res.Items) != 3 || res.Items[0].ID != "F-001" || res.Items[0].URL != base+"/browse/PEN-1" || res.URL != res.Items[0].URL {
		t.Fatalf("result %+v", res)
	}
	f := got[0]["fields"].(map[string]any)
	desc := f["description"].(string)
	if f["summary"] != "F-001 SQL injection" || f["project"].(map[string]any)["key"] != "PEN" || f["issuetype"].(map[string]any)["name"] != "Bug" ||
		f["priority"].(map[string]any)["name"] != "High" {
		t.Fatalf("fields %v", f)
	}
	for _, want := range []string{"h2. Description", "{code}\nid=1'\n{code}", "h3. Detail", "CVSS:3.1/AV:N/AC:H", "||Location|https://x/login"} {
		if !strings.Contains(desc, want) {
			t.Errorf("description lacks %q:\n%s", want, desc)
		}
	}
	if p := got[1]["fields"].(map[string]any)["priority"].(map[string]any)["name"]; p != "Medium" {
		t.Fatalf("medium priority %v", p)
	}
	// the server key is used without creds; errors never echo the key
	in.Creds = nil
	if _, err := r.Run(context.Background(), e, in); err == nil || !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "bad key") {
		t.Fatalf("server key: %v", err)
	}
	r.Getenv = func(k string) string { return map[string]string{"JIRA_USER": "bot", "JIRA_TOKEN": "own"}[k] }
	if _, err := r.Run(context.Background(), e, in); err == nil || strings.Contains(err.Error(), "own") {
		t.Fatalf("key echoed: %v", err)
	}
	r.Getenv = func(string) string { return "" }
	if _, err := r.Run(context.Background(), e, in); err == nil || !strings.Contains(err.Error(), "JIRA_TOKEN") {
		t.Fatalf("missing key: %v", err)
	}
	e.Jira.BaseURL = "http://jira.evil.example"
	in.Creds = &Creds{User: "a", Token: "b"}
	if _, err := r.Run(context.Background(), e, in); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("plain http: %v", err)
	}
}

func TestConfluenceSenderKey(t *testing.T) {
	var user string
	var title string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			io.WriteString(w, `{"results":[]}`)
			return
		}
		user, _, _ = r.BasicAuth()
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		title, _ = body["title"].(string)
		io.WriteString(w, `{"_links":{"base":"https://w","webui":"/p/1"}}`)
	}))
	defer srv.Close()
	r, _ := runner(t, "")
	e := Exporter{ID: "c", Type: "confluence", Confluence: &ConfluenceConf{BaseURL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), Space: "S", UserEnv: "CONFLUENCE_U", TokenEnv: "CONFLUENCE_T"}}
	in := input(t)
	in.Findings = in.Findings[1:2]
	in.Creds = &Creds{User: "pen1", Token: "k"}
	res, err := r.Run(context.Background(), e, in)
	if err != nil || user != "pen1" || res.URL != "https://w/p/1" || len(res.Items) != 1 || res.Items[0].ID != "F-001" {
		t.Fatalf("%v %q %+v", err, user, res)
	}
	if title != "F-001 SQL injection — ACME Web" {
		t.Fatalf("one finding is one page: %q", title)
	}
}

func unzip(t *testing.T, b []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		d, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = string(d)
	}
	return out
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A PDF without a template of its own uses the theme: the embedded LaTeX
// template and Lua filter, xelatex, the report HTML.
func TestPDFTheme(t *testing.T) {
	pb, pdir := fakePandoc(t, recordingPandoc)
	r, _ := runner(t, pb)
	res, err := r.Run(context.Background(), Exporter{ID: "pdf", Type: "pandoc", Format: "pdf"}, input(t))
	if err != nil {
		t.Fatal(err)
	}
	if res.Filename != "acme.pdf" || !bytes.Contains(res.Data, []byte(`<div class="rp-cover">`)) {
		t.Fatalf("%s", res.Filename)
	}
	args, _ := os.ReadFile(filepath.Join(pdir, "args.txt"))
	for _, want := range []string{"--template=", "report.latex", "--lua-filter=", "report.lua", "--pdf-engine=xelatex", "client=ACME"} {
		if !strings.Contains(string(args), want) {
			t.Errorf("args lack %q:\n%s", want, args)
		}
	}
}

// PDFs render two at a time, each within the PDF time limit.
func TestPDFWorker(t *testing.T) {
	pb, _ := fakePandoc(t, "sleep 0.4\n"+recordingPandoc)
	r, _ := runner(t, pb)
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Run(context.Background(), Exporter{ID: "pdf", Type: "pandoc", Format: "pdf"}, input(t)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if d := time.Since(start); d < 750*time.Millisecond {
		t.Fatalf("4 PDFs of 0.4s took %s: more than 2 at once", d)
	}
	pb, _ = fakePandoc(t, "sleep 5\n")
	r, _ = runner(t, pb)
	r.Timeout = time.Minute
	r.PDFTimeout = 300 * time.Millisecond
	start = time.Now()
	if _, err := r.Run(context.Background(), Exporter{ID: "pdf", Type: "pandoc", Format: "pdf"}, input(t)); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("no PDF time limit: %v after %s", err, time.Since(start))
	}
}

// PDFs waiting for a PDF worker hold no export worker: a DOCX asked for
// while four PDFs queue (two rendering until released, two waiting) runs.
func TestPDFQueueLeavesExports(t *testing.T) {
	pb, pdir := fakePandoc(t, "case \"$*\" in *xelatex*) while [ ! -e \"$(dirname \"$0\")/go\" ]; do sleep 0.05; done;; esac\n"+recordingPandoc)
	r, _ := runner(t, pb)
	r.Timeout = time.Minute
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.Run(context.Background(), Exporter{ID: "pdf", Type: "pandoc", Format: "pdf"}, input(t)); err != nil {
				t.Error(err)
			}
		}()
	}
	defer wg.Wait()
	// the PDFs finish once the test is done
	defer writeFile(t, pdir, "go", "", 0o644)
	// two render, then the other two queue
	waitFor(t, func() bool { return len(r.runQueue()) >= 2 })
	time.Sleep(100 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := r.Run(ctx, Exporter{ID: "docx", Type: "pandoc", Format: "docx"}, input(t)); err != nil {
		t.Fatalf("the DOCX behind four PDFs: %v", err)
	}
}

// The real thing, when pandoc and xelatex are installed.
func TestPDFReal(t *testing.T) {
	p, err := exec.LookPath("pandoc")
	if err != nil {
		t.Skip("pandoc not installed")
	}
	if _, err := exec.LookPath("xelatex"); err != nil {
		t.Skip("xelatex not installed")
	}
	r, _ := runner(t, p)
	r.Timeout = 2 * time.Minute
	// a real picture, and a broken one that must not sink the PDF
	in := imageInput(t, "http://169.254.169.254/x.png")
	in.Engagement.Start, in.Engagement.End = "2026-11-04", "2026-11-07"
	in.Findings[0].SetSection("Impact", "Header `Strict-Transport-Security` is missing ~~old~~ – 100 % & $5 #1 {x} \\ _y_ ^z\n\n![good](attachments/good.png)")
	var pic bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 40, 20))
	for x := 0; x < 40; x++ {
		img.Set(x, 10, color.RGBA{242, 107, 29, 255})
	}
	png.Encode(&pic, img)
	broken := in.Attachment
	in.Attachment = func(f *finding.Finding, rel string) ([]byte, bool) {
		if rel == "attachments/good.png" {
			return pic.Bytes(), true
		}
		return broken(f, rel)
	}
	res, err := r.Run(context.Background(), Exporter{ID: "pdf", Type: "pandoc", Format: "pdf"}, in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(res.Data, []byte("%PDF")) {
		t.Fatalf("not a PDF: %q", res.Data[:min(len(res.Data), 40)])
	}
	if !bytes.Contains(res.Data, []byte("/Subtype/Image")) && !bytes.Contains(res.Data, []byte("/Subtype /Image")) {
		t.Fatal("picture not in the PDF")
	}
}

func reportInput(t *testing.T) Input {
	in := input(t)
	in.Report = []ReportText{
		{Name: "Executive summary", Body: "We found **three** issues."},
		{Name: "Scope", Body: "The web portal.\n\n![x](attachments/shot.png)"},
		{Name: "Methodology", Body: "  \n"},
	}
	return in
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
