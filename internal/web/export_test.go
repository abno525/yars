package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"yars/internal/export"
)

const fakePandoc = `#!/bin/sh
out=""
while [ $# -gt 0 ]; do if [ "$1" = "-o" ]; then out="$2"; fi; shift; done
cat > "$out"
`

func (e *env) exporters(t *testing.T, pandocBody string) {
	t.Helper()
	dir := filepath.Join(e.dir, ".yars", "exporters")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "docx.yaml"), []byte("name: Client report (DOCX)\ntype: pandoc\nformat: docx\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "confluence.yaml"), []byte("name: Confluence HTML\ntype: confluence\nmark_reported: false\n"), 0o644)
	bin := filepath.Join(t.TempDir(), "pandoc")
	os.WriteFile(bin, []byte(pandocBody), 0o755)
	e.srv.Export = &export.Runner{Dir: dir, PandocPath: bin, HTTP: http.DefaultClient, Getenv: os.Getenv, Timeout: 5 * time.Second}
}

func TestExportDownload(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	b := e.do(t, "dora", "GET", "/e/acme/export", nil, nil).Body.String()
	if !strings.Contains(b, "Client report (DOCX)") || !strings.Contains(b, `id="pick-F-001-sql-injection" checked`) {
		t.Fatalf("export page:\n%s", b)
	}
	rec := e.do(t, "dora", "POST", "/e/acme/export", url.Values{"exporter": {"docx"}, "finding": {"F-001-sql-injection"}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Disposition"), `attachment; filename="acme.docx"`) || !strings.Contains(rec.Body.String(), "<h1>F-001 SQL injection</h1>") {
		t.Fatalf("code %d headers %v", rec.Code, rec.Header())
	}
	if e.status(t) != "reported" || e.lastCommit(t) != "dora|F-001: mark reported" {
		t.Fatalf("not reported: %s / %s", e.status(t), e.lastCommit(t))
	}
}

func TestExportMarksOnlyComplete(t *testing.T) {
	e := setup(t)
	e.exporters(t, fakePandoc)
	rec := e.do(t, "dora", "POST", "/e/acme/export", url.Values{"exporter": {"docx"}, "finding": {"F-001-sql-injection"}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "SQL injection") {
		t.Fatalf("code %d", rec.Code)
	}
	if e.status(t) != "draft" {
		t.Fatal("draft was marked")
	}
}

func TestExportFailureMarksNothing(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	e.exporters(t, "#!/bin/sh\necho 'pandoc: boom' >&2\nexit 1\n")
	rec := e.do(t, "dora", "POST", "/e/acme/export", url.Values{"exporter": {"docx"}, "finding": {"F-001-sql-injection"}}, nil)
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "boom") || rec.Header().Get("Content-Disposition") != "" {
		t.Fatalf("code %d", rec.Code)
	}
	if e.status(t) != "complete" {
		t.Fatal("marked after failure")
	}
}

func TestExportPentesterNoMark(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	rec := e.do(t, "alice", "POST", "/e/acme/export", url.Values{"exporter": {"docx"}, "finding": {"F-001-sql-injection"}}, nil)
	if rec.Code != 200 || e.status(t) != "complete" {
		t.Fatalf("code %d status %s", rec.Code, e.status(t))
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/export", url.Values{"exporter": {"confluence"}, "finding": {"F-001-sql-injection"}}, nil); rec.Code != 200 || e.status(t) != "complete" {
		t.Fatalf("mark_reported:false exporter marked: %d %s", rec.Code, e.status(t))
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/export", url.Values{"exporter": {"nope"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown exporter code %d", rec.Code)
	}
}
