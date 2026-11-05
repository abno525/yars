package web

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"yars/internal/config"
)

func TestAdminEngagements(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/admin/engagements", nil, nil).Body.String()
	for _, want := range []string{"<th>Engagement</th>", `<span class="mono" title="acme">acme</span>`, "ACME Web", `<span class="tag eng-active">Active</span>`, "Archive", "Add everyone"} {
		if !strings.Contains(b, want) {
			t.Fatalf("engagements page lacks %q:\n%s", want, b)
		}
	}
	// create with a team
	rec := e.do(t, "dora", "POST", "/admin/engagements", url.Values{"id": {"beta"}, "name": {"Beta"}, "client": {"B Corp"}, "member": {"alice", "ghost"}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	if m, _ := e.srv.Store.Members("beta"); !slices.Equal(m, []string{"alice"}) {
		t.Fatalf("team %v", m)
	}
	if rec := e.do(t, "dora", "POST", "/admin/engagements", url.Values{"id": {"../x"}, "name": {"X"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad id %d", rec.Code)
	}
	// everyone at once, then one off
	if rec := e.do(t, "dora", "POST", "/admin/engagements/beta/team", url.Values{"everyone": {"1"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("everyone %d", rec.Code)
	}
	if m, _ := e.srv.Store.Members("beta"); !slices.Equal(m, []string{"alice", "bob", "carol", "dora"}) {
		t.Fatalf("team %v", m)
	}
	e.do(t, "dora", "POST", "/admin/engagements/beta/team/remove", url.Values{"user": {"bob"}}, nil)
	e.do(t, "dora", "POST", "/admin/engagements/beta/team", url.Values{"user": {"bob"}}, nil)
	e.do(t, "dora", "POST", "/admin/engagements/beta/team/remove", url.Values{"user": {"carol"}}, nil)
	if m, _ := e.srv.Store.Members("beta"); !slices.Equal(m, []string{"alice", "bob", "dora"}) {
		t.Fatalf("team %v", m)
	}
	if b := e.do(t, "dora", "GET", "/admin/engagements?team=beta", nil, nil).Body.String(); !strings.Contains(b, `action="/admin/engagements/beta/team/remove"`) {
		t.Fatal("team editor missing")
	}
	// archive: the row stays, with its ID, tag and date; Reopen replaces Archive
	if rec := e.do(t, "dora", "POST", "/admin/engagements/acme/archive", url.Values{}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("archive %d", rec.Code)
	}
	b = e.do(t, "dora", "GET", "/admin/engagements?show=archived", nil, nil).Body.String()
	if !strings.Contains(b, ">acme<") || !strings.Contains(b, `<span class="tag eng-archived">Archived</span>`) || !strings.Contains(b, "/admin/engagements/acme/reopen") {
		t.Fatalf("archived row:\n%s", b)
	}
	if strings.Contains(b, ">beta<") {
		t.Fatal("active engagement under the archived filter")
	}
	// an admin who is not a director can archive but not reopen
	e.addUser(t, config.User{Username: "ann", Role: "pentester", IsAdmin: true})
	if b := e.do(t, "ann", "GET", "/admin/engagements?show=archived", nil, nil).Body.String(); strings.Contains(b, "/admin/engagements/acme/reopen") {
		t.Fatal("Reopen offered to an admin who is not a director")
	}
	if rec := e.do(t, "ann", "POST", "/admin/engagements/acme/reopen", url.Values{}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("reopen by admin pentester %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/engagements/acme/reopen", url.Values{}, nil); rec.Code != http.StatusSeeOther || e.srv.Store.Archived("acme") {
		t.Fatalf("reopen %d", rec.Code)
	}
	if rec := e.do(t, "dora", "POST", "/admin/engagements/nope/archive", url.Values{}, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown %d", rec.Code)
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
	if strings.Contains(b, "/findings/new") || !strings.Contains(b, `<span class="slot w128"></span>`) {
		t.Fatal("New finding on an archived board")
	}
	b = e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	for _, bad := range []string{"/action/", `/edit"`, `class="composer"`, `name="reply"`, `name="resolves"`, `hx-post="` + fpath + `/checks"`, "yarsComment"} {
		if strings.Contains(b, bad) {
			t.Errorf("archived finding page has %q", bad)
		}
	}
	if !strings.Contains(b, `<span class="tag eng-archived">Archived</span>`) || !strings.Contains(b, `<span class="slot w112"`) {
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
