package web

import (
	"net/url"
	"strconv"
	"testing"
)

// A board write that lands while the board is being rendered is not in the
// HTML, so the refresh URL's since must not include it either: the stamp is
// read before the content, and the next refresh re-renders.
func TestTeamBoardStampBeforeContent(t *testing.T) {
	e := setup(t)
	n := e.lead(t, "alice", "Verbose stack trace", "", "open")
	bob, _ := e.srv.Auth.Lookup("bob")
	carol, _ := e.srv.Auth.Lookup("carol")
	e.srv.boardRead = func() {
		e.srv.boardRead = nil
		if err := e.srv.Store.PostNote("acme", n.Num, "a reply mid render", bob); err != nil {
			t.Fatal(err)
		}
	}
	v, err := e.srv.teamBoardFor(carol, "acme", boardQuery{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(v.RefreshURL)
	if err != nil {
		t.Fatal(err)
	}
	now, err := e.srv.Store.NoteStamp("acme")
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("since") == strconv.FormatInt(now, 10) {
		t.Fatalf("since %s already covers the write the HTML lacks", u.Query().Get("since"))
	}
}
