package export

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yars/internal/config"
	"yars/internal/finding"
	"yars/internal/store"
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
	rt.SetMeta("retest", finding.Retest{Source: "old/F-003-xss", Result: "not_fixed"})
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

func TestExporterPathEscape(t *testing.T) {
	pb, _ := fakePandoc(t, recordingPandoc)
	r, edir := runner(t, pb)
	os.Symlink("/etc/hostname", filepath.Join(edir, "link.docx"))
	for _, tpl := range []string{"../x.docx", "/etc/hostname", "link.docx"} {
		if _, err := r.Run(context.Background(), Exporter{ID: "x", Type: "pandoc", Format: "docx", Template: tpl}, input(t)); err == nil || !strings.Contains(err.Error(), "outside") {
			t.Errorf("%s: %v", tpl, err)
		}
	}
	if _, err := r.Run(context.Background(), Exporter{ID: "s", Type: "script", Script: "../s.sh", Extension: "txt"}, input(t)); err == nil {
		t.Error("script escape accepted")
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
