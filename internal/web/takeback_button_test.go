package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/workflow"
)

// Take back has a button on the finding page (before: the bulk bar and MCP
// only). It stands right before Withdraw, for whoever may take the finding
// back (its author, a director) while it is in verification, in the plain
// button style of the reverts; Shift+T is its key and the ? list names it.
func TestTakeBackButton(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	bar := func(user string) string {
		t.Helper()
		return wfSection(t, e.do(t, user, "GET", fpath, nil, nil).Body.String())
	}
	const mark = `data-action="take_back"`
	if b := bar("alice"); strings.Contains(b, mark) {
		t.Fatalf("a draft has Take back:\n%s", b)
	}
	e.toVerification(t)
	if err := st.Transition("acme", fdir, workflow.Clear, "", wBob); err != nil {
		t.Fatal(err)
	}
	btn := `<form method="post" action="` + fshort + `/action/take_back" class="wf-action" data-slot="take_back"><button class="btn w112 secondary" id="wf-take_back" aria-keyshortcuts="Shift&#43;T" data-action="take_back" title="Take back">Take back</button></form>`
	for _, user := range []string{"alice", "dora"} {
		b := bar(user)
		i, w := strings.Index(b, btn), strings.Index(b, `id="wf-withdraw"`)
		if i < 0 || w < i {
			t.Fatalf("%s: no Take back before Withdraw:\n%s", user, b)
		}
	}
	// the author's two buttons stand side by side at the right edge: no
	// empty slot before, between or after them
	acts := between(bar("alice"), `<div class="wf-actions">`, "</div>")
	if strings.Contains(acts, `class="slot`) || strings.Count(acts, "data-slot=") != 2 {
		t.Errorf("alice's buttons:\n%s", acts)
	}
	// a reviewer's bar is as it was
	for _, user := range []string{"bob", "carol"} {
		if b := bar(user); strings.Contains(b, mark) || strings.Contains(b, "take_back") {
			t.Errorf("%s has Take back:\n%s", user, b)
		}
	}
	page := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(page, `<div class="krow" data-keys-for="Shift+T"><dt><kbd>Shift+T</kbd></dt><dd>Take back</dd></div>`) {
		t.Error("the ? list has no Shift+T row")
	}
	// the button's POST (the route was there before): back to draft, the
	// sign-off gone
	rec := e.do(t, "alice", "POST", fshort+"/action/take_back", url.Values{}, nil)
	if rec.Code != http.StatusSeeOther || e.status(t) != "draft" {
		t.Fatalf("take back: %d, status %s", rec.Code, e.status(t))
	}
	ref, err := st.Finding("acme", fdir)
	if err != nil || len(ref.F.Meta.ClearedBy) != 0 {
		t.Fatalf("sign-offs after take back: %v %v", ref.F.Meta.ClearedBy, err)
	}
	// complete: none
	for _, step := range []struct {
		act workflow.Action
		by  string
	}{{workflow.Submit, "alice"}, {workflow.Clear, "bob"}, {workflow.Approve, "dora"}} {
		u := wAlice
		switch step.by {
		case "bob":
			u = wBob
		case "dora":
			u = wDora
		}
		if err := st.Transition("acme", fdir, step.act, "", u); err != nil {
			t.Fatalf("%s: %v", step.act, err)
		}
	}
	for _, user := range []string{"alice", "dora"} {
		if b := bar(user); strings.Contains(b, mark) {
			t.Errorf("a complete finding has Take back for %s:\n%s", user, b)
		}
	}
}

// The simple workflow has no verification, so no bar of it has Take back.
func TestTakeBackButtonNotInSimple(t *testing.T) {
	e := setupSimple(t)
	for _, step := range []func(){func() {}, func() { e.toCompleteSimple(t) }} {
		step()
		for _, user := range []string{"anna", "ben"} {
			if b := wfSection(t, e.do(t, user, "GET", fpath, nil, nil).Body.String()); strings.Contains(b, "take_back") {
				t.Errorf("%s has Take back:\n%s", user, b)
			}
		}
	}
}
