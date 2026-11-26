package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
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
	if !strings.Contains(edit, `name="row:Location"`) || !strings.Contains(edit, `name="base"`) {
		t.Fatalf("editor:\n%s", edit)
	}
	rec := e.do(t, "alice", "POST", fpath+"/details", url.Values{"row:Location": {"https://x/login"}, "row:Attack condition": {"Account takeover"}}, nil)
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
	rec := e.do(t, "alice", "POST", fpath+"/details", url.Values{"row:Location": {"<script>alert(1)</script>"}}, nil)
	b := rec.Body.String()
	if !strings.Contains(b, "&lt;script&gt;") || strings.Contains(b, "<script>alert") {
		t.Fatalf("body:\n%s", b)
	}
}

func TestDetailsConflict(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "bob", "POST", fpath+"/details", url.Values{"row:Location": {"bob typed"}, "base": {"0000000000000000"}}, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "bob typed") {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
}

// Values are posted by row name: rows reordered in Admin › Structure while
// an editor is open keep each value under its name; a row that is gone is
// a conflict, not a silent save under another name.
func TestDetailsRowsChangedWhileEditing(t *testing.T) {
	e := setup(t)
	c := e.srv.conf()
	c.DetailsRows = []string{"Business impact", "Location", "Attack condition", "Cause", "Result"}
	e.srv.setConfig(c)
	rec := e.do(t, "alice", "POST", fpath+"/details", url.Values{"row:Location": {"/login"}, "row:Business impact": {"Takeover"}}, nil)
	if rec.Code != 200 {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
	ref, _ := e.srv.Store.Finding("acme", fdir)
	if d := ref.F.Meta.Details; d["Location"] != "/login" || d["Business impact"] != "Takeover" || d["Attack condition"] != "" {
		t.Fatalf("details %+v", d)
	}
	c.DetailsRows = []string{"Endpoint", "Cause", "Result", "Attack condition", "Business impact"}
	e.srv.setConfig(c)
	before := e.lastCommit(t)
	rec = e.do(t, "alice", "POST", fpath+"/details", url.Values{"row:Attack condition": {"Logged out"}, "row:Gone": {"x"}}, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "Logged out") || e.lastCommit(t) != before {
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
	e.do(t, "alice", "POST", fpath+"/details", url.Values{"row:Location": {"x"}}, nil)
	if !strings.Contains(e.meta(t), "Old row: legacy") {
		t.Fatalf("file:\n%s", e.meta(t))
	}
}
