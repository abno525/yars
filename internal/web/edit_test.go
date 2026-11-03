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

func TestCreateFindingFlow(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"Reflected XSS"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/F-002-reflected-xss" {
		t.Fatalf("code %d loc %q", rec.Code, rec.Header().Get("Location"))
	}
	if got := e.lastCommit(t); got != "alice|F-002: create" {
		t.Fatalf("commit %q", got)
	}
	if rec := e.do(t, "alice", "GET", "/e/acme/findings/new", nil, nil); rec.Code != 200 {
		t.Fatalf("form code %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"  "}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty title code %d", rec.Code)
	}
	if rec := e.do(t, "alice", "POST", "/e/nope/findings/new", url.Values{"title": {"x"}}, nil); rec.Code != 404 {
		t.Fatalf("unknown engagement code %d", rec.Code)
	}
}

func TestEditSectionCommits(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "bob", "GET", "/e/acme/f/F-001-sql-injection/s/Impact/edit", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<textarea") {
		t.Fatalf("edit form code %d", rec.Code)
	}
	rec = e.do(t, "bob", "POST", "/e/acme/f/F-001-sql-injection/s/Impact", url.Values{"body": {"Attacker reads **all** data."}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<strong>all</strong>") {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	if got := e.lastCommit(t); got != "bob|F-001: edit Impact" {
		t.Fatalf("commit %q", got)
	}
	rec = e.do(t, "bob", "POST", "/e/acme/f/F-001-sql-injection/s/Steps%20to%20Reproduce", url.Values{"body": {"1. go"}}, nil)
	if rec.Code != 200 || e.lastCommit(t) != "bob|F-001: edit Steps to Reproduce" {
		t.Fatalf("spaced section: code %d commit %q", rec.Code, e.lastCommit(t))
	}
}

func TestNewEngagementForbiddenForPentester(t *testing.T) {
	e := setup(t)
	form := url.Values{"id": {"2026-12-x"}, "name": {"X"}, "client": {"X Corp"}}
	if rec := e.do(t, "alice", "POST", "/engagements/new", form, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("pentester code %d", rec.Code)
	}
	rec := e.do(t, "dora", "POST", "/engagements/new", form, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/2026-12-x" {
		t.Fatalf("director code %d loc %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := e.do(t, "dora", "POST", "/engagements/new", url.Values{"id": {"../x"}, "name": {"X"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad id code %d", rec.Code)
	}
}

func TestNoGlobalNewFinding(t *testing.T) {
	e := setup(t)
	for _, m := range []string{"GET", "POST"} {
		if rec := e.do(t, "alice", m, "/findings/new", url.Values{"title": {"x"}}, nil); rec.Code != 404 {
			t.Fatalf("%s code %d", m, rec.Code)
		}
	}
}

func TestExtraSectionEditable(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Notes", "n", "", gitrepo.Author{Name: "x", Email: "x@x"}); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "bob", "POST", "/e/acme/f/F-001-sql-injection/s/Notes", url.Values{"body": {"updated"}}, nil); rec.Code != 200 {
		t.Fatalf("Notes code %d", rec.Code)
	}
	if rec := e.do(t, "bob", "POST", "/e/acme/f/F-001-sql-injection/s/Bogus", url.Values{"body": {"x"}}, nil); rec.Code != 404 {
		t.Fatalf("Bogus code %d", rec.Code)
	}
	b, _ := os.ReadFile(filepath.Join(e.dir, "engagements/acme/findings/F-001-sql-injection/finding.md"))
	if strings.Contains(string(b), "Bogus") {
		t.Fatal("Bogus section written")
	}
}

func TestEditFormCarriesBase(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "bob", "GET", "/e/acme/f/F-001-sql-injection/s/Impact/edit", nil, nil)
	if !strings.Contains(rec.Body.String(), `name="base"`) {
		t.Fatal("editor form has no base field")
	}
}

func TestEditConflict409(t *testing.T) {
	e := setup(t)
	form := url.Values{"body": {"bob text"}, "base": {"0000000000000000"}}
	rec := e.do(t, "bob", "POST", "/e/acme/f/F-001-sql-injection/s/Impact", form, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "changed by someone else") {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "bob text") {
		t.Fatal("user's text not kept in the editor")
	}
}

func TestEditInvalidBody400(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "bob", "POST", "/e/acme/f/F-001-sql-injection/s/Impact", url.Values{"body": {"x\n## Remediation\ny"}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "reserved for sections") {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}

func TestCrossOriginPostRejected(t *testing.T) {
	e := setup(t)
	hdr := map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}
	rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"x"}}, hdr)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d", rec.Code)
	}
	if rec := e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"pw"}}, hdr); rec.Code != http.StatusForbidden {
		t.Fatalf("login CSRF code %d", rec.Code)
	}
}

func TestPreview(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", "/e/acme/preview", url.Values{"body": {"# Hi\n<script>x</script>"}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<h1") || strings.Contains(rec.Body.String(), "<script>") {
		t.Fatalf("code %d body %s", rec.Code, rec.Body.String())
	}
}
