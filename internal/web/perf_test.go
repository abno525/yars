package web

import (
	"net/url"
	"testing"

	"yars/internal/gitrepo"
)

// Pages start no git process once the index is warm.
func TestPagesStartNoGit(t *testing.T) {
	e := setup(t)
	pages := []string{"/", "/inbox", "/e/acme", fpath, fpath + "/chat"}
	for _, p := range pages {
		if c := e.do(t, "bob", "GET", p, nil, nil).Code; c != 200 {
			t.Fatalf("%s: %d", p, c)
		}
	}
	for _, p := range pages {
		n := gitrepo.Spawned()
		e.do(t, "bob", "GET", p, nil, nil)
		if got := gitrepo.Spawned() - n; got != 0 {
			t.Errorf("%s: %d git processes", p, got)
		}
	}
}

// The inbox is classified once per index generation and user, not per
// request; a change shows at once.
func TestInboxCachedPerGeneration(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	bob, _ := e.srv.Auth.Lookup("bob")
	engs, _ := e.srv.Index.Engagements()
	v1, err := e.srv.inboxFor(bob, engs)
	if err != nil || len(v1.Review) != 1 {
		t.Fatalf("review %+v %v", v1.Review, err)
	}
	b0 := e.srv.inboxes.builds
	v2, _ := e.srv.inboxFor(bob, engs)
	if e.srv.inboxes.builds != b0 || &v2.Review[0] != &v1.Review[0] {
		t.Fatal("inbox rebuilt without a change")
	}
	e.do(t, "bob", "POST", fpath+"/action/clear", url.Values{}, nil)
	if v3, _ := e.srv.inboxFor(bob, engs); len(v3.Review) != 0 || e.srv.inboxes.builds == b0 {
		t.Fatalf("change not seen: %+v", v3.Review)
	}
}
