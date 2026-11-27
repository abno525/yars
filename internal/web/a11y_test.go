package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/workflow"
)

// A reviewer's chip on the workflow bar says a sign-off in words too, not
// by its colour alone: the hidden " (signed off)" the findings list has.
func TestSignedOffChipSaysSo(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	open := `<span class="rev" title="bob"><span class="name">bob</span></span>`
	if b := wfSection(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String()); !strings.Contains(b, open) || strings.Contains(b, `class="sr"`) {
		t.Fatalf("an open reviewer's chip:\n%s", b)
	}
	if err := e.srv.Store.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	b := wfSection(t, e.do(t, "dora", "GET", fpath, nil, nil).Body.String())
	if !strings.Contains(b, `<span class="rev cleared" title="bob"><span class="name">bob</span><span class="sr"> (signed off)</span></span>`) {
		t.Fatalf("the signed-off chip is colour only:\n%s", b)
	}
}

// Go to's list is a listbox of options: each row has the role, and the
// selected one says so (the first as the list arrives; the arrows and the
// pointer move it in app.js, by one function).
func TestGoToRowsAreOptions(t *testing.T) {
	e := setup(t)
	a := e.authorOf(wAlice)
	e.srv.Store.CreateFinding("acme", "Stored injection in notes", a)
	e.srv.Store.CreateFinding("acme", "Blind injection in search", a)
	rec := e.do(t, "alice", "GET", "/go/search?q=injection", nil, map[string]string{"HX-Request": "true"})
	b := rec.Body.String()
	if rec.Code != http.StatusOK || strings.Count(b, `<a class="res`) != 3 {
		t.Fatalf("code %d:\n%s", rec.Code, b)
	}
	if !strings.Contains(b, `<a class="res sel" href="/e/acme/f/001" role="option" aria-selected="true">`) {
		t.Errorf("the first row:\n%s", b)
	}
	if n := strings.Count(b, `role="option" aria-selected="true"`); n != 1 {
		t.Errorf("%d rows selected", n)
	}
	if n := strings.Count(b, `role="option" aria-selected="false">`); n != 2 {
		t.Errorf("%d other options, want 2:\n%s", n, b)
	}
	if page := e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(); !strings.Contains(page, `<div id="goto-results" class="gotores" role="listbox">`) {
		t.Error("the list is no listbox")
	}
	// a pin of the script: the pointer moves the selection as the arrows do
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	for _, w := range []string{"function yarsGotoSel(to)",
		"r.classList.toggle('sel', r === to); r.setAttribute('aria-selected', r === to ? 'true' : 'false');",
		"if (r && !r.classList.contains('sel')) yarsGotoSel(r);"} {
		if !strings.Contains(app, w) {
			t.Errorf("app.js lacks %s", w)
		}
	}
	if strings.Contains(app, "r.classList.add('sel');") {
		t.Error("the pointer moves the class without aria-selected")
	}
}
