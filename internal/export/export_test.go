package export

import (
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

func TestMarkdownLayout(t *testing.T) {
	md := Markdown(input(t))
	i1, i2, i3 := strings.Index(md, "# F-001 SQL injection"), strings.Index(md, "# F-003 XSS"), strings.Index(md, "# F-002 Missing HSTS")
	if i1 < 0 || !(i1 < i2 && i2 < i3) {
		t.Fatalf("order/headings:\n%s", md)
	}
	for _, want := range []string{
		"| Severity | high |",
		"| CVSS | 7.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N) |",
		"| Location | https://x/login<br>param user |",
		"| Attack Complexity | High | race with refresh |",
		"| Retest result | Not fixed |",
		"## Description",
		"### Detail",
		"DB read | all rows.", // section bodies are Markdown, not table cells
	} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in:\n%s", want, md)
		}
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
	if res.Filename != "acme.docx" || !bytes.Contains(res.Data, []byte("# F-001 SQL injection")) {
		t.Fatalf("result %s %q", res.Filename, res.Data[:min(len(res.Data), 80)])
	}
	args, _ := os.ReadFile(filepath.Join(pdir, "args.txt"))
	for _, want := range []string{"-f\ngfm", "-t\ndocx", "--reference-doc=" + filepath.Join(edir, "ref.docx"), "--toc", "title=ACME Web"} {
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

func TestConfluencePushErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"bad token tok123"}`)
	}))
	defer srv.Close()
	r, _ := runner(t, "")
	r.Getenv = func(k string) string { return map[string]string{"CU": "bot", "CT": "tok123"}[k] }
	e := Exporter{ID: "c", Type: "confluence", Confluence: &ConfluenceConf{BaseURL: strings.Replace(srv.URL, "127.0.0.1", "localhost", 1), Space: "S", UserEnv: "CU", TokenEnv: "CT"}}
	_, err := r.Run(context.Background(), e, input(t))
	if err == nil || strings.Contains(err.Error(), "tok123") || !strings.Contains(err.Error(), "401") {
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
