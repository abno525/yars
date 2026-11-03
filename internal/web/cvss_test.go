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

const fpath = "/e/acme/f/F-001-sql-injection"

func vecForm(over map[string]string) url.Values {
	f := url.Values{}
	for k, v := range map[string]string{"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"} {
		f.Set(k, v)
	}
	for k, v := range over {
		if v == "" {
			f.Del(k)
		} else {
			f.Set(k, v)
		}
	}
	return f
}

func (e *env) meta(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.dir, "engagements", "acme", "findings", "F-001-sql-injection", "finding.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCVSSCalcLive(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", fpath+"/cvss/calc", vecForm(nil), nil)
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, "7.4") || !strings.Contains(b, "high") || !strings.Contains(b, `name="reason_AC"`) {
		t.Fatalf("code %d body:\n%s", rec.Code, b)
	}
	if strings.Contains(b, `name="reason_AV"`) {
		t.Fatal("reason input shown for standard metric")
	}
}

func TestCVSSSave(t *testing.T) {
	e := setup(t)
	edit := e.do(t, "alice", "GET", fpath+"/cvss/edit", nil, nil)
	if !strings.Contains(edit.Body.String(), `name="base"`) {
		t.Fatal("editor has no base")
	}
	f := vecForm(map[string]string{"reason_AC": "race condition"})
	rec := e.do(t, "alice", "POST", fpath+"/cvss", f, nil)
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, "7.4") || !strings.Contains(b, "race condition") {
		t.Fatalf("code %d body:\n%s", rec.Code, b)
	}
	m := e.meta(t)
	if !strings.Contains(m, "cvss: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N") || !strings.Contains(m, "AC: race condition") {
		t.Fatalf("file:\n%s", m)
	}
	if got := e.lastCommit(t); got != "alice|F-001: set CVSS 7.4" {
		t.Fatalf("commit %q", got)
	}
}

func TestCVSSSaveIncomplete(t *testing.T) {
	e := setup(t)
	before := e.lastCommit(t)
	rec := e.do(t, "alice", "POST", fpath+"/cvss", vecForm(map[string]string{"A": ""}), nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `name="AV"`) {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
	if e.lastCommit(t) != before {
		t.Fatal("commit made")
	}
}

func TestCVSSConflict(t *testing.T) {
	e := setup(t)
	f := vecForm(map[string]string{"reason_AC": "bob reason", "base": "0000000000000000"})
	rec := e.do(t, "bob", "POST", fpath+"/cvss", f, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "bob reason") {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
}

func TestCVSSMissingReasonWarns(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", fpath+"/cvss", vecForm(nil), nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "reason missing") {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
}

func TestCVSSPaste(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", fpath+"/cvss/calc", url.Values{"paste": {"cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h"}}, nil)
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, "9.8") || !strings.Contains(b, `name="C" value="H" checked`) {
		t.Fatalf("code %d body:\n%s", rec.Code, b)
	}
	rec = e.do(t, "alice", "POST", fpath+"/cvss/calc", url.Values{"paste": {"junk"}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "prefix") {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
}

func TestFindingForeignCVSS(t *testing.T) {
	e := setup(t)
	ref, _ := e.srv.Store.Finding("acme", "F-001-sql-injection")
	ref.F.SetMeta("cvss", "8.1")
	ref.F.SetMeta("severity", "medium")
	rel := filepath.Join("engagements", "acme", "findings", "F-001-sql-injection", "finding.md")
	os.WriteFile(filepath.Join(e.dir, rel), ref.F.Bytes(), 0o644)
	e.srv.Store.Repo().Commit([]string{rel}, "ext", gitrepo.Author{Name: "x", Email: "x@x"})

	rec := e.do(t, "alice", "GET", fpath, nil, nil)
	b := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(b, "Not a CVSS 3.1 base vector") || !strings.Contains(b, "sev-medium") {
		t.Fatalf("code %d body:\n%s", rec.Code, b)
	}
}

func TestSeverityManual(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", fpath+"/severity", url.Values{"severity": {"low"}}, nil)
	if rec.Code != 200 || !strings.Contains(e.meta(t), "severity: low") {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
	e.do(t, "alice", "POST", fpath+"/cvss", vecForm(nil), nil)
	rec = e.do(t, "alice", "POST", fpath+"/severity", url.Values{"severity": {"low"}}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestFindingPageHasCVSSPanel(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, `id="cvss"`) || strings.Index(b, `id="cvss"`) > strings.Index(b, "<h2>Description</h2>") {
		t.Fatalf("CVSS panel missing or after sections:\n%s", b)
	}
}
