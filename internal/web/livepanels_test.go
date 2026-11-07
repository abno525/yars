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
		"cvss": fshort + "/cvss?live=1", "s-impact": fshort + "/s/Impact?live=1"} {
		tag := openTag(t, b, id)
		if !strings.Contains(tag, `hx-get="`+url+`"`) || !strings.Contains(tag, "sse:content") || !strings.Contains(tag, "sse:resync") || !strings.Contains(tag, "data-sse") {
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
