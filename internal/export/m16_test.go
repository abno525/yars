package export

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"yars/internal/finding"
)

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
		if r.Method != "POST" || r.URL.Path != "/rest/api/2/issue" || !ok || u != "pen1@acme" || p != "own" {
			w.WriteHeader(401)
			io.WriteString(w, `{"errorMessages":["bad key own"]}`)
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
	os.Symlink("/etc/hostname", filepath.Join(repo, "link"))
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

// Pictures that don't decode are left out of a PDF (xelatex would fail on
// them); other formats keep them.
func TestPDFDropsBrokenImages(t *testing.T) {
	in := imageInput(t, "http://x/y.png")
	in.strictImages = true
	if x := XHTML(in, false); strings.Contains(x, "data:image/png") || strings.Count(x, "image removed") != 3 {
		t.Fatalf("broken image kept:\n%s", x)
	}
}
