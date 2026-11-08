package web

import (
	"net/url"
	"regexp"
	"strings"
	"testing"

	"yars/internal/finding"
)

// R5: a finding without a severity shows "—" in the board's Severity
// cell, not an empty cell.
func TestNoSeverityIsADash(t *testing.T) {
	e := setup(t)
	e.srv.Store.UpdateSeverity("acme", fdir, "low", "", e.authorOf(wAlice))
	e.second(t, "alice")
	tbl := between(e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(), `id="findings"`, "</table>")
	sev := regexp.MustCompile(`</a></td>\s*<td>(.*?)</td>\s*<td class="num">`)
	if m := sev.FindStringSubmatch(between(tbl, "F-002", "</tr>")); m == nil || m[1] != `<span class="muted">—</span>` {
		t.Fatalf("no severity: %q", m)
	}
	if m := sev.FindStringSubmatch(between(tbl, "F-001", "</tr>")); m == nil || !strings.Contains(m[1], "sev-low") {
		t.Fatalf("a severity: %q", m)
	}
}

// R5 (P3): the inbox queues' Severity column shows the same "—".
func TestInboxNoSeverityIsADash(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String()
	cells := regexp.MustCompile(`<td class="c-tag">(.*?)</td>\s*<td class="c-eng mono"[^>]*><span class="engid">acme</span> · <span class="fid">F-001</span>`).FindAllStringSubmatch(b, -1)
	if len(cells) == 0 {
		t.Fatalf("no F-001 inbox row:\n%s", b)
	}
	for _, c := range cells {
		if c[1] != `<span class="muted">—</span>` {
			t.Errorf("severity cell %q", c[1])
		}
	}
}

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
	// the new-finding template picker
	nf := e.do(t, "alice", "GET", "/e/acme/findings/new", nil, nil).Body.String()
	if r := between(nf, "Bad vector", "</tr>"); !strings.Contains(r, `class="num">—<`) {
		t.Fatalf("new-finding picker:\n%s", r)
	}
	// the CVSS calculator with metrics missing: the same dash
	calc := e.do(t, "alice", "POST", fpath+"/cvss/calc", url.Values{"AV": {"N"}}, nil).Body.String()
	if !strings.Contains(calc, `<span class="scorebox">—</span>`) {
		t.Fatalf("calculator:\n%s", calc)
	}
	page := e.do(t, "alice", "GET", "/templates/bad-vector", nil, nil).Body.String()
	if !regexp.MustCompile(`<span class="tag score">—</span>`).MatchString(page) || strings.Contains(page, `<span class="tag score">0.0</span>`) {
		t.Fatalf("template page:\n%s", page)
	}
}
