package web

import (
	"regexp"
	"strings"
	"testing"

	"yars/internal/finding"
)

// D20: no or an invalid CVSS vector shows "—", never "0.0", on the board,
// the templates list and the template page; a valid vector scoring 0.0
// still shows 0.0.
func TestNoScoreIsADash(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	// F-001: an invalid vector; F-002: a valid one that scores 0.0
	st.UpdateSeverity("acme", fdir, "low", "", e.authorOf(wAlice))
	d2 := e.second(t, "alice")
	if err := st.UpdateCVSS("acme", d2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", nil, "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	tbl := between(e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(), `id="findings"`, "</table>")
	if r := between(tbl, "F-001", "</tr>"); !strings.Contains(r, `class="num">—<`) {
		t.Fatalf("no score:\n%s", r)
	}
	if r := between(tbl, "F-002", "</tr>"); !strings.Contains(r, `class="num">0.0<`) {
		t.Fatalf("a real 0.0:\n%s", r)
	}
	// a template with a broken vector
	err := st.SaveTemplate("bad-vector", e.authorOf(wDora), func(*finding.Finding) (*finding.Finding, error) {
		f := st.NewTemplate("Bad vector")
		return f, f.SetMeta("cvss", "CVSS:3.1/AV:X")
	})
	if err != nil {
		t.Fatal(err)
	}
	list := e.do(t, "alice", "GET", "/templates", nil, nil).Body.String()
	if r := between(list, "Bad vector", "</tr>"); !strings.Contains(r, `class="num">—<`) {
		t.Fatalf("templates list:\n%s", r)
	}
	page := e.do(t, "alice", "GET", "/templates/bad-vector", nil, nil).Body.String()
	if !regexp.MustCompile(`<span class="tag score">—</span>`).MatchString(page) || strings.Contains(page, `<span class="tag score">0.0</span>`) {
		t.Fatalf("template page:\n%s", page)
	}
}
