package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// The list of accounts that could join a team is made only for those who
// can change the team: a member who cannot sees the team alone, and the
// page's data holds no other account for a template to show.
func TestAccountListOnlyForTeamManagers(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.DB().AddUser(config.User{Username: "zed", Role: "reviewer", PasswordHash: pwHash}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		user    string
		canTeam bool
	}{{"alice", false}, {"bob", false}, {"dora", true}} {
		v := engSettingsView{CanTeam: c.canTeam}
		if err := e.srv.teamLists(&v, "acme"); err != nil {
			t.Fatal(err)
		}
		if len(v.Members) != 3 {
			t.Fatalf("%s: team %+v", c.user, v.Members)
		}
		if has := len(v.Others) > 0; has != c.canTeam {
			t.Fatalf("%s: other accounts %+v", c.user, v.Others)
		}
		b := e.do(t, c.user, "GET", "/e/acme/settings", nil, nil).Body.String()
		form := strings.Contains(b, `action="/e/acme/settings/team"`)
		if strings.Contains(b, "zed") != c.canTeam || form != c.canTeam {
			t.Fatalf("%s: account zed shown %v, add form %v", c.user, strings.Contains(b, "zed"), form)
		}
	}
	// an archived engagement has no add form, so no list either
	if err := e.srv.Store.Archive("acme", wDora); err != nil {
		t.Fatal(err)
	}
	if b := e.do(t, "dora", "GET", "/e/acme/settings", nil, nil).Body.String(); strings.Contains(b, "zed") {
		t.Fatal("an archived engagement lists the other accounts")
	}
}

// Q8: a director and a reviewer save a finding as a template; a pentester
// is refused, on the form and on the save, and no template is made.
func TestSaveAsTemplateByRole(t *testing.T) {
	e := setup(t)
	for _, method := range []string{"GET", "POST"} {
		var form url.Values
		if method == "POST" {
			form = url.Values{"title": {"By a pentester"}}
		}
		if rec := e.do(t, "alice", method, fshort+"/template", form, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("pentester %s: code %d", method, rec.Code)
		}
	}
	if ts, err := e.srv.Store.Templates(); err != nil || len(ts) != 0 {
		t.Fatalf("templates after a refused save: %+v %v", ts, err)
	}
	for user, title := range map[string]string{"bob": "By a reviewer", "dora": "By a director"} {
		if rec := e.do(t, user, "POST", fshort+"/template", url.Values{"title": {title}}, nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("%s: code %d %s", user, rec.Code, rec.Body.String())
		}
	}
	if ts, err := e.srv.Store.Templates(); err != nil || len(ts) != 2 {
		t.Fatalf("templates %+v %v", ts, err)
	}
}
