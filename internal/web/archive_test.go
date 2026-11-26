package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// The team routes refuse an archived engagement themselves, not only the
// page that hides the form: a director's or an admin's POST is 403 and the
// team stays. After a reopen both routes work.
func TestArchivedTeamRoutesRefused(t *testing.T) {
	e := setup(t)
	e.pen2(t) // on the team
	e.addUser(t, config.User{Username: "pen3", Role: "pentester"})
	dora, _ := e.srv.Auth.Lookup("dora")
	if err := e.srv.Store.Archive("acme", dora); err != nil {
		t.Fatal(err)
	}
	team := func() string {
		t.Helper()
		m, err := e.srv.Store.Members("acme")
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(m, ",")
	}
	before := team()
	if rec := e.do(t, "dora", "POST", "/e/acme/settings/team", url.Values{"user": {"pen3"}}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("add on an archived engagement: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/settings/team/remove", url.Values{"user": {"pen2"}}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("remove on an archived engagement: %d", rec.Code)
	}
	if team() != before {
		t.Fatalf("team changed from %s to %s", before, team())
	}
	if rec := e.do(t, "pen3", "GET", "/e/acme", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("the account not added opens the archived engagement: %d", rec.Code)
	}
	// reopened: both work
	if rec := e.do(t, "dora", "POST", "/e/acme/reopen", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("reopen %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/settings/team", url.Values{"user": {"pen3"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("add after reopening: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/settings/team/remove", url.Values{"user": {"pen2"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("remove after reopening: %d", rec.Code)
	}
	if got := team(); !strings.Contains(got, "pen3") || strings.Contains(got, "pen2") {
		t.Fatalf("team after reopening: %s", got)
	}
}

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
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); strings.Contains(between(b, "<main>", "</main>"), "/reopen") {
		t.Fatal("Reopen offered to a pentester")
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/reopen", url.Values{}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("reopen by pentester %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/e/acme/reopen", url.Values{}, nil); rec.Code != http.StatusSeeOther || e.srv.Store.Archived("acme") {
		t.Fatalf("reopen %d", rec.Code)
	}
}
