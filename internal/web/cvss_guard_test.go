package web

import (
	"net/url"
	"regexp"
	"strings"
	"testing"
)

var cvssChecked = regexp.MustCompile(`name="([A-Z]+)" value="([A-Z])" checked`)

// cvssFormTag is the opening tag of the CVSS editor's form.
func cvssFormTag(t *testing.T, html string) string {
	t.Helper()
	i := strings.Index(html, `<form class="flush" hx-post="/e/acme/f/001/cvss"`)
	if i < 0 {
		t.Fatalf("no CVSS editor form:\n%s", html)
	}
	return html[i : i+strings.Index(html[i:], ">")+1]
}

// 5.2: the CVSS editor is guarded. Each metric click draws the editor again
// with the server's values, so the browser sees no changed field: the
// server says when the editor as drawn is not what it opened with.
func TestCVSSEditorGuard(t *testing.T) {
	e := setup(t)
	calc := func(f url.Values) string {
		t.Helper()
		rec := e.do(t, "alice", "POST", fpath+"/cvss/calc", f, nil)
		if rec.Code != 200 {
			t.Fatalf("calc %d:\n%s", rec.Code, rec.Body.String())
		}
		return cvssFormTag(t, rec.Body.String())
	}
	// a finding without a vector opens with the team standards picked:
	// guarded, nothing unsaved
	open := e.do(t, "alice", "GET", fpath+"/cvss/edit", nil, nil).Body.String()
	if tag := cvssFormTag(t, open); !strings.Contains(tag, " data-guard") || strings.Contains(tag, "data-unsaved") {
		t.Fatalf("fresh editor: %s", tag)
	}
	start := url.Values{}
	for _, m := range cvssChecked.FindAllStringSubmatch(open, -1) {
		start.Set(m[1], m[2])
	}
	if len(start) == 0 {
		t.Fatalf("the fresh editor picks nothing:\n%s", open)
	}
	if tag := calc(start); !strings.Contains(tag, " data-guard") || strings.Contains(tag, "data-unsaved") {
		t.Fatalf("the start values drawn again: %s", tag)
	}
	moved := url.Values{}
	for k, v := range start {
		moved[k] = v
	}
	moved.Set("AV", map[bool]string{true: "L", false: "N"}[start.Get("AV") == "N"])
	if tag := calc(moved); !strings.Contains(tag, " data-guard data-unsaved") {
		t.Fatalf("a moved metric is not unsaved: %s", tag)
	}
	// a refused save keeps the mark
	if rec := e.do(t, "alice", "POST", fpath+"/cvss", vecForm(map[string]string{"A": ""}), nil); !strings.Contains(cvssFormTag(t, rec.Body.String()), "data-unsaved") {
		t.Fatalf("refused save %d: %s", rec.Code, cvssFormTag(t, rec.Body.String()))
	}

	// with a stored vector the editor starts from it
	if rec := e.do(t, "alice", "POST", fpath+"/cvss", vecForm(map[string]string{"reason_AC": "race condition"}), nil); rec.Code != 200 {
		t.Fatalf("save %d", rec.Code)
	}
	if tag := cvssFormTag(t, e.do(t, "alice", "GET", fpath+"/cvss/edit", nil, nil).Body.String()); strings.Contains(tag, "data-unsaved") {
		t.Fatalf("editor of a stored vector: %s", tag)
	}
	if tag := calc(vecForm(map[string]string{"reason_AC": "race condition"})); strings.Contains(tag, "data-unsaved") {
		t.Fatalf("the stored values drawn again: %s", tag)
	}
	if tag := calc(vecForm(map[string]string{"reason_AC": "another reason"})); !strings.Contains(tag, "data-unsaved") {
		t.Fatalf("a changed reason is not unsaved: %s", tag)
	}
	if tag := calc(vecForm(map[string]string{"reason_AC": "race condition", "C": "L"})); !strings.Contains(tag, "data-unsaved") {
		t.Fatalf("a moved metric of a stored vector is not unsaved: %s", tag)
	}
}
