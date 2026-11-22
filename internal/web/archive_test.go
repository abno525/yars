package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// An archived engagement's pages are read only: its ID and an Archived tag
// with the date show, every edit control is gone and its place kept.
func TestArchivedPageNoEditForms(t *testing.T) {
	e := setup(t)
	e.rules(t, styleRules, nil)
	dora, _ := e.srv.Auth.Lookup("dora")
	if err := e.srv.Store.Archive("acme", dora); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	if !strings.Contains(b, `<span class="tag eng-archived">Archived</span>`) || !strings.Contains(b, `<span class="idchip">acme</span>`) {
		t.Fatalf("board:\n%s", b)
	}
	if strings.Contains(between(b, "<main>", "</main>"), "/findings/new") || !strings.Contains(b, `<span class="slot w128"></span>`) {
		t.Fatal("New finding on an archived board")
	}
	b = e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	for _, bad := range []string{"/action/", `/edit"`, `class="composer"`, `name="reply"`, `name="resolves"`, `hx-post="` + fpath + `/checks"`, "yarsComment"} {
		if strings.Contains(b, bad) {
			t.Errorf("archived finding page has %q", bad)
		}
	}
	if !strings.Contains(b, `<span class="tag eng-archived">Archived</span>`) || !strings.Contains(b, `<div class="wf-actions">`) {
		t.Fatal("archived finding page: no tag or no kept slots")
	}
	// directors reopen from the board
	if b := e.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String(); !strings.Contains(b, `action="/e/acme/reopen"`) {
		t.Fatal("no Reopen for the director")
	}
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); strings.Contains(b, "/reopen") {
		t.Fatal("Reopen offered to a pentester")
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/reopen", url.Values{}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("reopen by pentester %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/reopen", url.Values{}, nil); rec.Code != http.StatusSeeOther || e.srv.Store.Archived("acme") {
		t.Fatalf("reopen %d", rec.Code)
	}
}
