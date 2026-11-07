package web

import (
	"regexp"
	"strings"
	"testing"
)

// livePanel is the opening tag of the element with id in b.
func openTag(t *testing.T, b, id string) string {
	t.Helper()
	m := regexp.MustCompile(`<(section|div)[^>]*id="` + id + `"[^>]*>`).FindString(b)
	if m == "" {
		t.Fatalf("no #%s:\n%s", id, b)
	}
	return m
}

// D15: the read panels of a finding (title, Details, assets, CVSS, each
// section) refetch themselves on content changes and resyncs (a push); an
// open editor has no trigger, so typing is never replaced.
func TestFindingPanelsRefreshLive(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	for id, url := range map[string]string{"fhead": fshort + "/head", "details": fshort + "/details", "assets": fshort + "/assets",
		"cvss": fshort + "/cvss", "s-impact": fshort + "/s/Impact"} {
		tag := openTag(t, b, id)
		if !strings.Contains(tag, `hx-get="`+url+`?live=1&amp;h=`) || !strings.Contains(tag, "sse:content") || !strings.Contains(tag, "sse:resync") || !strings.Contains(tag, "data-sse") {
			t.Errorf("#%s does not refresh live: %s", id, tag)
		}
	}
	for _, p := range []string{"/details/edit", "/assets/edit", "/cvss/edit", "/s/Impact/edit"} {
		if ed := e.do(t, "alice", "GET", fpath+p, nil, nil).Body.String(); strings.Contains(ed, "sse:content") {
			t.Errorf("%s editor refreshes itself:\n%s", p, ed)
		}
	}
	// an MCP edit: the panels' answers show it
	st := e.srv.Store
	st.UpdateSection("acme", fdir, "Impact", "changed by the assistant", "", e.authorOf(wAlice))
	st.UpdateTitle("acme", fdir, "Blind SQL injection", e.authorOf(wAlice))
	st.UpdateDetails("acme", fdir, map[string]string{"Location": "POST /api"}, "", e.authorOf(wAlice))
	if s := e.do(t, "alice", "GET", fpath+"/s/Impact?live=1", nil, nil).Body.String(); !strings.Contains(s, "changed by the assistant") || !strings.Contains(s, "sse:content") {
		t.Fatalf("section refresh:\n%s", s)
	}
	if h := e.do(t, "alice", "GET", fpath+"/head", nil, nil).Body.String(); !strings.Contains(h, "<h1 title=\"Blind SQL injection\"") || !strings.Contains(h, `id="sevpill"`) {
		t.Fatalf("head refresh:\n%s", h)
	}
	if d := e.do(t, "alice", "GET", fpath+"/details", nil, nil).Body.String(); !strings.Contains(d, "POST /api") {
		t.Fatalf("details refresh:\n%s", d)
	}
}

// A live refresh of a panel that is still current answers 204 (nothing to
// swap, nothing rendered): a push to another finding or a poll tick costs
// little. Once the finding changed it answers the new panel.
func TestLiveRefreshUnchangedIs204(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	urls := map[string]string{}
	for _, id := range []string{"fhead", "details", "assets", "cvss", "s-impact"} {
		m := regexp.MustCompile(`hx-get="([^"]+)"`).FindStringSubmatch(openTag(t, b, id))
		urls[id] = strings.ReplaceAll(m[1], "&amp;", "&")
	}
	for id, u := range urls {
		if rec := e.do(t, "alice", "GET", u, nil, nil); rec.Code != 204 || rec.Body.Len() != 0 {
			t.Errorf("%s unchanged: %d %q", id, rec.Code, rec.Body.String())
		}
	}
	e.srv.Store.UpdateSection("acme", fdir, "Impact", "new impact", "", e.authorOf(wAlice))
	for id, u := range urls {
		if rec := e.do(t, "alice", "GET", u, nil, nil); rec.Code != 200 {
			t.Errorf("%s changed: %d", id, rec.Code)
		}
	}
	// a status change (no file change) refreshes too: the lock depends on it
	e.toVerification(t)
	ref, _ := e.srv.Store.Finding("acme", fdir)
	if rec := e.do(t, "alice", "GET", fshort+"/head?live=1&h="+e.srv.liveKey(ref), nil, nil); rec.Code != 204 {
		t.Fatalf("current key: %d", rec.Code)
	}
}

// A finding that is gone (deleted or merged away by a push) reloads the
// page from any live refresh instead of keeping stale panels.
func TestLiveRefreshGoneReloads(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/head?live=1&h=x", "/details?live=1&h=x", "/s/Impact?live=1&h=x"} {
		rec := e.do(t, "alice", "GET", "/e/acme/f/999"+p, nil, nil)
		if rec.Header().Get("HX-Refresh") != "true" {
			t.Errorf("%s: %d, no HX-Refresh", p, rec.Code)
		}
	}
}

// A live refresh of a section is not Cancel: the user's presence (an
// editor open in another tab) stays.
func TestLiveRefreshKeepsPresence(t *testing.T) {
	e := setup(t)
	e.do(t, "alice", "GET", fpath+"/s/Impact/edit", nil, nil)
	e.do(t, "alice", "GET", fpath+"/s/Impact?live=1", nil, nil)
	if p := e.do(t, "bob", "GET", fpath+"/s/Impact?live=1", nil, nil).Body.String(); !strings.Contains(p, "alice") {
		t.Fatalf("alice's presence gone after a live refresh:\n%s", p)
	}
	e.do(t, "alice", "GET", fpath+"/s/Impact", nil, nil) // Cancel
	if p := e.do(t, "bob", "GET", fpath+"/s/Impact?live=1", nil, nil).Body.String(); strings.Contains(p, "alice") {
		t.Fatalf("presence after Cancel:\n%s", p)
	}
}

// The refresh endpoints check access like the page: an outsider gets
// nothing.
func TestLiveRefreshAccess(t *testing.T) {
	e := setup(t)
	e.outsider(t)
	for _, p := range []string{"/head", "/details", "/assets", "/cvss?live=1", "/s/Impact?live=1"} {
		rec := e.do(t, "eve", "GET", fpath+p, nil, nil)
		if rec.Code == 200 || strings.Contains(rec.Body.String(), "SQL injection") {
			t.Errorf("%s answered an outsider %d", p, rec.Code)
		}
	}
}
