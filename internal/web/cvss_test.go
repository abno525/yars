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

// The calculator belongs to the editor: on a finding the user may not edit
// it is refused as the editor is, instead of drawing an editor that cannot
// save (backlog, M3).
func TestCVSSCalcLocked(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	for _, path := range []string{"/cvss/edit", "/cvss/calc"} {
		method := map[string]string{"/cvss/edit": "GET", "/cvss/calc": "POST"}[path]
		rec := e.do(t, "alice", method, fpath+path, vecForm(nil), nil)
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), `name="reason_AC"`) {
			t.Errorf("%s on a complete finding: %d", path, rec.Code)
		}
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
	er, _ := e.srv.Store.EngRepo("acme")
	if err := er.Commit([]string{"findings/F-001-sql-injection/finding.md"}, "ext", gitrepo.Author{Name: "x", Email: "x@x"}); err != nil {
		t.Fatal(err)
	}

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

// The saved CVSS panel lists every non-standard metric in a table with
// headers: metric, the team standard, the chosen value and the reason.
func TestCVSSReasonsTableInView(t *testing.T) {
	e := setup(t)
	form := vecForm(nil)
	for _, k := range []string{"AC", "C", "I"} {
		form.Set("reason_"+k, "because "+k)
	}
	e.do(t, "alice", "POST", fpath+"/cvss", form, nil)
	b := e.do(t, "alice", "GET", fpath+"/cvss", nil, nil).Body.String()
	for _, h := range []string{"<th class=\"c-metric\">Metric</th>", "<th class=\"c-chosen\">Chosen</th>", "<th>Reason</th>", "because C"} {
		if !strings.Contains(b, h) {
			t.Fatalf("missing %q in CVSS panel:\n%s", h, b)
		}
	}
	if strings.Contains(b, "Standard</th>") {
		t.Fatal("the standard column is implied and not shown")
	}
}

func TestCVSSExplanationTableUnderCalculator(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "POST", fpath+"/cvss/calc", vecForm(nil), nil).Body.String()
	tbl := strings.Index(b, "Reasoning")
	paste := strings.Index(b, `name="paste"`)
	for _, k := range []string{"AC", "C", "I"} {
		i := strings.Index(b, `<textarea name="reason_`+k+`"`)
		if i < 0 || i < tbl || tbl < paste {
			t.Fatalf("reason_%s textarea missing or not in table under calculator:\n%s", k, b)
		}
	}
	if strings.Contains(b, `name="reason_A"`) || strings.Contains(b, `name="reason_AV"`) {
		t.Fatal("explanation asked for a metric at its standard value")
	}
}

func TestCVSSEditorStartsAtNone(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath+"/cvss/edit", nil, nil).Body.String()
	for _, k := range []string{"C", "I", "A"} {
		if !strings.Contains(b, `name="`+k+`" value="N" checked`) {
			t.Fatalf("%s not preselected None:\n%s", k, b)
		}
	}
	if strings.Index(b, `name="C" value="N"`) > strings.Index(b, `name="C" value="H"`) {
		t.Fatal("None is not the first option")
	}
}

func TestCVSSReasonKeptWhenToggled(t *testing.T) {
	e := setup(t)
	// AC switched back to standard while a typed reason exists: kept as hidden field
	b := e.do(t, "alice", "POST", fpath+"/cvss/calc", vecForm(map[string]string{"AC": "L", "reason_AC": "typed text"}), nil).Body.String()
	if !strings.Contains(b, `type="hidden" name="reason_AC" value="typed text"`) {
		t.Fatalf("typed reason dropped:\n%s", b)
	}
	b = e.do(t, "alice", "POST", fpath+"/cvss/calc", vecForm(map[string]string{"AC": "H", "reason_AC": "typed text"}), nil).Body.String()
	if !strings.Contains(b, `<textarea name="reason_AC" rows="2">typed text</textarea>`) {
		t.Fatalf("typed reason not restored:\n%s", b)
	}
}

// A stored reason explains the stored value. The editor does not offer it
// for another value: the field is empty and counted as missing, and a Save
// that posts the old words for the new value stores no reason. Back at the
// stored value the reason shows again and a Save keeps it; words typed for
// the new value are kept, also the same words.
func TestCVSSEditorReasonGoesWithItsValue(t *testing.T) {
	e := setup(t)
	form := func(over map[string]string) url.Values {
		f := vecForm(map[string]string{"PR": "L", "reason_PR": "low account", "reason_AC": "race", "reason_C": "c", "reason_I": "i"})
		for k, v := range over {
			f.Set(k, v)
		}
		return f
	}
	if rec := e.do(t, "alice", "POST", fpath+"/cvss", form(nil), nil); rec.Code != 200 || !strings.Contains(e.meta(t), "PR: low account") {
		t.Fatalf("first save %d:\n%s", rec.Code, e.meta(t))
	}
	const mark = `<input type="hidden" name="reasoncut_PR" value="1">`
	// PR:L to PR:H, the page sends the stored words along
	b := e.do(t, "alice", "POST", fpath+"/cvss/calc", form(map[string]string{"PR": "H"}), nil).Body.String()
	if !strings.Contains(b, `<textarea name="reason_PR" rows="2" aria-invalid="true" placeholder="Required"></textarea>`) || !strings.Contains(b, `<span class="pstate error">1 reason missing</span>`) || !strings.Contains(b, mark) {
		t.Fatalf("the old reason is offered for the new value:\n%s", between(b, `<div class="reasoning flush">`, "</form>"))
	}
	if !strings.Contains(b, `<textarea name="reason_AC" rows="2">race</textarea>`) {
		t.Fatal("the reason of a metric that did not change is gone")
	}
	// back to PR:L with the emptied field: the stored reason shows again
	back := map[string]string{"reason_PR": "", "reasoncut_PR": "1"}
	b = e.do(t, "alice", "POST", fpath+"/cvss/calc", form(back), nil).Body.String()
	if !strings.Contains(b, `<textarea name="reason_PR" rows="2">low account</textarea>`) || strings.Contains(b, "reasoncut_PR") || strings.Contains(b, "missing</span>") {
		t.Fatalf("the stored reason did not come back:\n%s", between(b, `<div class="reasoning flush">`, "</form>"))
	}
	// and a Save from there keeps it
	if rec := e.do(t, "alice", "POST", fpath+"/cvss", form(back), nil); rec.Code != 200 || !strings.Contains(e.meta(t), "PR: low account") {
		t.Fatalf("there and back lost the reason (%d):\n%s", rec.Code, e.meta(t))
	}
	// words typed into the emptied field are the user's, also the same words
	typed := map[string]string{"PR": "H", "reasoncut_PR": "1"}
	b = e.do(t, "alice", "POST", fpath+"/cvss/calc", form(typed), nil).Body.String()
	if !strings.Contains(b, `<textarea name="reason_PR" rows="2">low account</textarea>`) || !strings.Contains(b, mark) {
		t.Fatalf("typed words were emptied:\n%s", between(b, `<div class="reasoning flush">`, "</form>"))
	}
	if rec := e.do(t, "alice", "POST", fpath+"/cvss", form(typed), nil); rec.Code != 200 || !strings.Contains(e.meta(t), "PR:H/") || !strings.Contains(e.meta(t), "PR: low account") {
		t.Fatalf("typed reason not saved (%d):\n%s", rec.Code, e.meta(t))
	}
	// a Save that changes the value and posts the stored words: no reason
	rec := e.do(t, "alice", "POST", fpath+"/cvss", form(nil), nil)
	if m := e.meta(t); rec.Code != 200 || !strings.Contains(m, "PR:L/") || strings.Contains(m, "low account") || !strings.Contains(m, "AC: race") {
		t.Fatalf("the old reason was saved for the new value (%d):\n%s", rec.Code, m)
	}
	if !strings.Contains(rec.Body.String(), "reason missing") {
		t.Fatalf("the panel does not say the reason is missing:\n%s", rec.Body.String())
	}
}

func TestCVSSEditorUIGuards(t *testing.T) {
	e := setup(t)
	e.do(t, "alice", "POST", fpath+"/cvss", vecForm(nil), nil)
	b := e.do(t, "alice", "GET", fpath+"/cvss/edit", nil, nil).Body.String()
	for _, want := range []string{
		`id="cvss-AV-N"`,                 // radios keep focus across swaps
		`hx-sync="closest form:replace"`, // fast clicks don't race
		`data-enter`,                     // Enter in paste box applies (app.js)
		`data-confirm=`,                  // clear asks first
	} {
		if !strings.Contains(b, want) {
			t.Fatalf("missing %q:\n%s", want, b)
		}
	}
}

func TestSeverityConflict(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, `name="base"`) {
		t.Fatal("severity form has no base")
	}
	rec := e.do(t, "bob", "POST", fpath+"/severity", url.Values{"severity": {"low"}, "base": {"0000000000000000"}}, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "The finding changed since you read it") {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
}

func TestFindingPageHasCVSSPanel(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, `id="cvss"`) || strings.Index(b, `id="cvss"`) > strings.Index(b, "<h2>Description</h2>") {
		t.Fatalf("CVSS panel missing or after sections:\n%s", b)
	}
}
