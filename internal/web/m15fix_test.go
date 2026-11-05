package web

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// A disabled account is no reviewer: not in the list, not added by "all",
// refused when posted or bulk assigned.
func TestDisabledNotReviewer(t *testing.T) {
	e := setup(t)
	e.srv.Store.DB().SetDisabled("carol", true)
	if b := e.do(t, "alice", "GET", fpath+"/workflow", nil, nil).Body.String(); strings.Contains(b, "carol") {
		t.Fatal("reviewer list offers a disabled account")
	}
	if rec := e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"reviewer": {"carol"}}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("assigned a disabled account: %d", rec.Code)
	}
	e.do(t, "alice", "POST", fpath+"/reviewers", url.Values{"all": {"1"}}, nil)
	ref, _ := e.srv.Store.Finding("acme", fdir)
	if slices.Contains(ref.F.Meta.Reviewers, "carol") || !slices.Contains(ref.F.Meta.Reviewers, "bob") {
		t.Fatalf("all: %v", ref.F.Meta.Reviewers)
	}
	e.do(t, "dora", "POST", "/e/acme/bulk", url.Values{"action": {"reviewers"}, "id": {"001"}, "reviewer": {"carol"}}, nil)
	if ref, _ := e.srv.Store.Finding("acme", fdir); slices.Contains(ref.F.Meta.Reviewers, "carol") {
		t.Fatalf("bulk added a disabled account: %v", ref.F.Meta.Reviewers)
	}
}

// /engagements/new puts the ticked people and the creator on the team, so a
// director without the admin flag doesn't make an engagement nobody sees.
func TestNewEngagementTeam(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/engagements/new", nil, nil).Body.String()
	for _, n := range []string{"alice", "bob", "carol"} {
		if !strings.Contains(b, `name="member" value="`+n+`"`) {
			t.Fatalf("no checkbox for %s:\n%s", n, b)
		}
	}
	form := url.Values{"id": {"beta"}, "name": {"Beta"}, "member": {"alice", "bob", "nobody"}}
	if rec := e.do(t, "dora", "POST", "/engagements/new", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	got, err := e.srv.Store.Members("beta")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if strings.Join(got, ",") != "alice,bob,dora" {
		t.Fatalf("team %v", got)
	}
	if rec := e.do(t, "alice", "GET", "/e/beta", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("team member can't open it: %d", rec.Code)
	}
	if rec := e.do(t, "carol", "GET", "/e/beta", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("non-member opens it: %d", rec.Code)
	}
}
