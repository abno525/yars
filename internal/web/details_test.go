package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/gitrepo"
)

func TestDetailsView(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	loc, ac, bi := strings.Index(b, "Location"), strings.Index(b, "Attack condition"), strings.Index(b, "Business impact")
	desc, det, cv := strings.Index(b, "<h2>Description</h2>"), strings.Index(b, `id="details"`), strings.Index(b, `id="cvss"`)
	if loc < 0 || !(loc < ac && ac < bi && bi < desc) || det < 0 || det > cv {
		t.Fatalf("order wrong:\n%s", b)
	}
}

func TestDetailsSave(t *testing.T) {
	e := setup(t)
	edit := e.do(t, "alice", "GET", fpath+"/details/edit", nil, nil).Body.String()
	if !strings.Contains(edit, `name="row_0"`) || !strings.Contains(edit, `name="base"`) {
		t.Fatalf("editor:\n%s", edit)
	}
	rec := e.do(t, "alice", "POST", fpath+"/details", url.Values{"row_0": {"https://x/login"}, "row_1": {"Account takeover"}}, nil)
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, "https://x/login") || !strings.Contains(b, "Account takeover") {
		t.Fatalf("code %d body:\n%s", rec.Code, b)
	}
	if !strings.Contains(e.meta(t), "Location: https://x/login") {
		t.Fatalf("file:\n%s", e.meta(t))
	}
	if got := e.lastCommit(t); got != "alice|F-001: edit details" {
		t.Fatalf("commit %q", got)
	}
}

func TestDetailsEscaped(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", fpath+"/details", url.Values{"row_0": {"<script>alert(1)</script>"}}, nil)
	b := rec.Body.String()
	if !strings.Contains(b, "&lt;script&gt;") || strings.Contains(b, "<script>alert") {
		t.Fatalf("body:\n%s", b)
	}
}

func TestDetailsConflict(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "bob", "POST", fpath+"/details", url.Values{"row_0": {"bob typed"}, "base": {"0000000000000000"}}, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "bob typed") {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
}

func TestDetailsOtherKeys(t *testing.T) {
	e := setup(t)
	ref, _ := e.srv.Store.Finding("acme", "F-001-sql-injection")
	ref.F.SetMeta("details", map[string]string{"Old row": "legacy"})
	rel := filepath.Join("engagements", "acme", "findings", "F-001-sql-injection", "finding.md")
	os.WriteFile(filepath.Join(e.dir, rel), ref.F.Bytes(), 0o644)
	er, _ := e.srv.Store.EngRepo("acme")
	if err := er.Commit([]string{"findings/F-001-sql-injection/finding.md"}, "ext", gitrepo.Author{Name: "x", Email: "x@x"}); err != nil {
		t.Fatal(err)
	}

	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, "Other") || !strings.Contains(b, "Old row") {
		t.Fatalf("body:\n%s", b)
	}
	e.do(t, "alice", "POST", fpath+"/details", url.Values{"row_0": {"x"}}, nil)
	if !strings.Contains(e.meta(t), "Old row: legacy") {
		t.Fatalf("file:\n%s", e.meta(t))
	}
}
