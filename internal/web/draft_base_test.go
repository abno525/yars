package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
)

var baseRe = regexp.MustCompile(`name="base" value="([^"]*)"`)

// editorBase is the base hash an editor's form carries.
func editorBase(t *testing.T, html string) string {
	t.Helper()
	m := baseRe.FindStringSubmatch(html)
	if m == nil {
		t.Fatalf("editor has no base:\n%s", html)
	}
	return m[1]
}

// jsFunc cuts the text of app.js from start up to end.
func jsFunc(t *testing.T, js, start, end string) string {
	t.Helper()
	i := strings.Index(js, start)
	if i < 0 {
		t.Fatalf("script lacks %s", start)
	}
	j := strings.Index(js[i:], end)
	if j < 0 {
		t.Fatalf("script lacks %s after %s", end, start)
	}
	return js[i : i+j]
}

// 5.1: a kept draft carries the base its editor was opened with. Restored
// into an editor opened later, it is saved against that base, so a
// colleague's text written meanwhile shows as a conflict and is not
// overwritten.
func TestDraftRestoreKeepsBase(t *testing.T) {
	e := setup(t)
	// the editor the draft was written in
	old := editorBase(t, e.do(t, "alice", "GET", fpath+"/s/Impact/edit", nil, nil).Body.String())
	// a colleague saves meanwhile
	if err := e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Impact", "carol's newer text", "", gitrepo.Author{Name: "carol", Email: "carol@yars.local"}); err != nil {
		t.Fatal(err)
	}
	// the editor opened after the new login has the newer base
	fresh := editorBase(t, e.do(t, "alice", "GET", fpath+"/s/Impact/edit", nil, nil).Body.String())
	if fresh == old {
		t.Fatal("the base did not follow the colleague's save")
	}
	// the draft's own base: the conflict view, nothing saved
	rec := e.do(t, "alice", "POST", fpath+"/s/Impact", url.Values{"body": {"alice's draft"}, "base": {old}}, nil)
	if c := rec.Body.String(); rec.Code != http.StatusConflict || !strings.Contains(c, "Changed by carol") || !strings.Contains(c, ">Keep mine<") {
		t.Fatalf("draft's base %d:\n%s", rec.Code, c)
	}
	ref, _ := e.srv.Store.Finding("acme", "F-001-sql-injection")
	if body, _ := ref.F.Section("Impact"); !strings.Contains(body, "carol's newer text") {
		t.Fatalf("the colleague's text is gone: %q", body)
	}
	// a draft of an earlier version has no base: the one Restore puts in
	// its place matches no text either
	rec = e.do(t, "alice", "POST", fpath+"/s/Impact", url.Values{"body": {"alice's draft"}, "base": {"none"}}, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("base none %d", rec.Code)
	}

	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	// the draft is written with the form's base
	if fn := jsFunc(t, js, "function yarsExpired()", "\n}\n"); !strings.Contains(fn, "input[name=base]") || !strings.Contains(fn, "base: ") {
		t.Fatalf("yarsExpired keeps no base:\n%s", fn)
	}
	// Restore puts it back, and "none" for a draft without one
	i := strings.Index(js, "closest('[data-draft-restore]')")
	if i < 0 {
		t.Fatal("no Restore handler")
	}
	fn := js[i : i+strings.Index(js[i:], "\n});")]
	if !strings.Contains(fn, "input[name=base]") || !strings.Contains(fn, "d.base") || !strings.Contains(fn, "'none'") {
		t.Fatalf("Restore leaves the fresh editor's base:\n%s", fn)
	}
	// a conflict (409) or a refused text (400) is no error to htmx: the
	// draft goes only when the answer closed the editor
	i = strings.LastIndex(js, "'htmx:afterRequest'")
	fn = js[i : i+strings.Index(js[i:], "\n});")]
	if strings.Contains(fn, "detail.successful") || !strings.Contains(fn, "status < 200") {
		t.Fatalf("the draft is dropped on a conflict:\n%s", fn)
	}
}
