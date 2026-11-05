package web

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/store"
	"yars/internal/workflow"
)

// addUser adds an account and logs it in.
func (e *env) addUser(t *testing.T, u config.User) {
	t.Helper()
	u.PasswordHash = pwHash
	if err := e.srv.Store.DB().AddUser(u); err != nil {
		t.Fatal(err)
	}
	tok, ok := e.srv.Auth.Login(u.Username, "pw")
	if !ok {
		t.Fatal("login failed")
	}
	e.toks[u.Username] = tok
}

// Engagements are for their team: others get 404 everywhere (pages,
// fragments, writes, the event stream) and don't see them listed.
func TestTeamOnly(t *testing.T) {
	e := setup(t)
	e.addUser(t, config.User{Username: "pen2", Role: "pentester"})
	if err := e.srv.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta Corp"}, gitrepo.Author{Name: "dora", Email: "d@x"}); err != nil {
		t.Fatal(err)
	}
	e.srv.Store.DB().AddMembers("beta", "pen2")
	for _, p := range []string{"/e/acme", fpath, fpath + "/chat", fpath + "/workflow", "/events?eng=acme", "/e/acme/export"} {
		if rec := e.do(t, "pen2", "GET", p, nil, nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s by non-member: %d", p, rec.Code)
		}
		if p != "/events?eng=acme" { // (a member's stream never ends)
			if rec := e.do(t, "alice", "GET", p, nil, nil); rec.Code != 200 {
				t.Errorf("GET %s by member: %d", p, rec.Code)
			}
		}
	}
	if rec := e.do(t, "pen2", "POST", fpath+"/chat", url.Values{"text": {"hi"}}, nil); rec.Code != http.StatusNotFound {
		t.Errorf("chat by non-member: %d", rec.Code)
	}
	home := e.do(t, "pen2", "GET", "/", nil, nil).Body.String()
	if strings.Contains(home, "ACME Web") || !strings.Contains(home, "Beta Corp") {
		t.Fatalf("pen2's home:\n%s", home)
	}
	// alice's switcher lists acme only; dora (director) sees both
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); strings.Contains(b, "Beta Corp") {
		t.Fatal("alice sees beta")
	}
	if b := e.do(t, "dora", "GET", "/e/acme", nil, nil).Body.String(); !strings.Contains(b, "Beta Corp") {
		t.Fatal("director doesn't see beta")
	}
	// an admin who is not a director sees everything too
	e.addUser(t, config.User{Username: "ann", Role: "pentester", IsAdmin: true})
	if rec := e.do(t, "ann", "GET", "/e/beta", nil, nil); rec.Code != 200 {
		t.Fatalf("admin on beta: %d", rec.Code)
	}
}

// A stream of every engagement carries only the user's teams' events.
func TestStreamTeamOnly(t *testing.T) {
	e := setup(t)
	a := gitrepo.Author{Name: "dora", Email: "d@x"}
	e.srv.Store.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, a)
	ref, err := e.srv.Store.CreateFinding("beta", "Other", a)
	if err != nil {
		t.Fatal(err)
	}
	ts := e.liveServer(t)
	s := e.openSSE(t, ts, "", nil) // alice, every engagement
	s.waitFor(t, "id: ")
	dora, _ := e.srv.Auth.Lookup("dora")
	if _, err := e.srv.Store.PostChat("beta", ref.Dir, chat.Message{Text: "secret"}, dora); err != nil {
		t.Fatal(err)
	}
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"mine"}}, nil)
	if l := s.waitFor(t, "data: "); !strings.Contains(l, `"eng":"acme"`) {
		t.Fatalf("first event %q: another team's engagement leaked", l)
	}
}

// The inbox lists only findings of the user's teams.
func TestInboxTeamOnly(t *testing.T) {
	e := setup(t)
	e.addUser(t, config.User{Username: "rev2", Role: "reviewer"})
	ref, _ := e.srv.Store.Finding("acme", fdir)
	alice, _ := e.srv.Auth.Lookup("alice")
	e.srv.Store.SetReviewers("acme", ref.Dir, []string{"rev2"}, alice)
	e.srv.Store.UpdateSeverity("acme", ref.Dir, "high", "", alice)
	if err := e.srv.Store.Transition("acme", ref.Dir, workflow.Submit, "", alice); err != nil {
		t.Fatal(err)
	}
	if b := e.do(t, "rev2", "GET", "/inbox", nil, nil).Body.String(); strings.Contains(b, "SQL injection") {
		t.Fatal("inbox shows another team's finding")
	}
	e.srv.Store.DB().AddMembers("acme", "rev2")
	if b := e.do(t, "rev2", "GET", "/inbox", nil, nil).Body.String(); !strings.Contains(b, "SQL injection") {
		t.Fatal("inbox misses the team's finding")
	}
}

// Only the engagement's team can be assigned as reviewers: the list, the
// "all" button, a posted name and bulk assign.
func TestReviewersFromTeam(t *testing.T) {
	e := setup(t)
	e.addUser(t, config.User{Username: "rev2", Role: "reviewer"})
	if b := e.do(t, "alice", "GET", fpath+"/workflow", nil, nil).Body.String(); strings.Contains(b, "rev2") {
		t.Fatal("reviewer list offers someone off the team")
	}
	if rec := e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"reviewer": {"rev2"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("assigned someone off the team: %d", rec.Code)
	}
	e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"all": {"1"}}, nil)
	if ref, _ := e.srv.Store.Finding("acme", fdir); slices.Contains(ref.F.Meta.Reviewers, "rev2") {
		t.Fatalf("all added someone off the team: %v", ref.F.Meta.Reviewers)
	}
	b := e.do(t, "dora", "POST", "/e/acme/bulk", url.Values{"action": {"reviewers"}, "id": {"001"}, "reviewer": {"rev2"}}, nil).Body.String()
	if ref, _ := e.srv.Store.Finding("acme", fdir); slices.Contains(ref.F.Meta.Reviewers, "rev2") {
		t.Fatalf("bulk added someone off the team:\n%s", b)
	}
	e.srv.Store.DB().AddMembers("acme", "rev2")
	if b := e.do(t, "alice", "GET", fpath+"/workflow", nil, nil).Body.String(); !strings.Contains(b, "rev2") {
		t.Fatal("team reviewer missing from the list")
	}
}

// An archived engagement can be read but not changed.
func TestArchivedReadOnly(t *testing.T) {
	e := setup(t)
	dora, _ := e.srv.Auth.Lookup("dora")
	if err := e.srv.Store.Archive("acme", dora); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "alice", "GET", fpath, nil, nil); rec.Code != 200 {
		t.Fatalf("read: %d", rec.Code)
	}
	rec := e.do(t, "alice", "POST", fpath+"/chat", url.Values{"text": {"hi"}}, map[string]string{"HX-Request": "true"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "archived") {
		t.Fatalf("chat on archived: %d %s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "alice", "POST", fpath+"/action/submit", url.Values{}, map[string]string{"HX-Request": "true"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("transition on archived: %d", rec.Code)
	}
}

// The admin pages follow the admin flag, not the role.
func TestAdminFlag(t *testing.T) {
	e := setup(t)
	e.addUser(t, config.User{Username: "dir2", Role: "director"})
	e.addUser(t, config.User{Username: "ann", Role: "pentester", IsAdmin: true})
	if rec := e.do(t, "dir2", "GET", "/admin/rules", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("director without the flag: %d", rec.Code)
	}
	if b := e.do(t, "dir2", "GET", "/", nil, nil).Body.String(); strings.Contains(b, `href="/admin"`) {
		t.Fatal("Admin nav shown without the flag")
	}
	if rec := e.do(t, "ann", "GET", "/admin", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("admin pentester: %d", rec.Code)
	}
	if b := e.do(t, "ann", "GET", "/", nil, nil).Body.String(); !strings.Contains(b, `href="/admin"`) {
		t.Fatal("Admin nav missing for an admin")
	}
}

// The theme toggle stores the choice; the server's value is on <html>.
func TestThemeSaved(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", "/", nil, nil).Body.String(); strings.Contains(b, `<html lang="en" data-theme=`) {
		t.Fatal("theme set before any choice")
	}
	if rec := e.do(t, "alice", "POST", "/settings/theme", url.Values{"theme": {"dark"}}, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("save: %d", rec.Code)
	}
	if b := e.do(t, "alice", "GET", "/", nil, nil).Body.String(); !strings.Contains(b, `<html lang="en" data-theme="dark"`) {
		t.Fatalf("theme not applied:\n%.400s", b)
	}
	if rec := e.do(t, "alice", "POST", "/settings/theme", url.Values{"theme": {"pink"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad theme: %d", rec.Code)
	}
	if rec := e.do(t, "", "POST", "/settings/theme", url.Values{"theme": {"dark"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("logged out: %d", rec.Code)
	}
	if b := e.do(t, "", "GET", "/login", nil, nil).Body.String(); strings.Contains(b, "data-theme-save") {
		t.Fatal("login page saves the theme")
	}
}

func TestExportAudited(t *testing.T) {
	e := setup(t)
	e.toComplete(t)
	e.exporters(t, fakePandoc)
	if rec := e.do(t, "alice", "POST", "/e/acme/export", url.Values{"dest": {"docx"}, "finding": {"F-001-sql-injection"}}, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("export %d", rec.Code)
	}
	l, _ := e.srv.Store.DB().AuditLog(1)
	if len(l) != 1 || l[0].Action != "export" || l[0].Actor != "alice" || l[0].Target != "acme" || l[0].Detail != "docx, 1 findings" {
		t.Fatalf("audit %+v", l)
	}
}

// Disabled accounts are logged out at once.
func TestDisabledLoggedOut(t *testing.T) {
	e := setup(t)
	e.srv.Store.DB().SetDisabled("alice", true)
	if rec := e.do(t, "alice", "GET", "/", nil, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("disabled account: %d", rec.Code)
	}
}
