package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

var evRe = regexp.MustCompile(`\?ev=([0-9a-f]{40})`)

func TestHistoryPage(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	e.toVerification(t)
	if err := st.UpdateSection("acme", fdir, "Impact", "Read the user table.", "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSection("acme", fdir, "Impact", "Read and change the user table.\nData loss.", "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	// the finding page links its history
	if b := e.do(t, "alice", "GET", fshort, nil, nil).Body.String(); !strings.Contains(b, `class="btn secondary w136" href="`+fshort+`/history"`) {
		t.Fatalf("no History button:\n%s", b)
	}
	rec := e.do(t, "bob", "GET", fshort+"/history", nil, nil)
	b := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	for _, want := range []string{"edited Impact", "created", "submit", `class="ev`, "Back"} {
		if !strings.Contains(b, want) {
			t.Fatalf("missing %q:\n%s", want, b)
		}
	}
	noInline(t, "history", b)
	evs := evRe.FindAllStringSubmatch(b, -1)
	if len(evs) < 3 {
		t.Fatalf("event links %v", evs)
	}
	newest := evs[0][1]
	// the newest edit is selected by default and shows its diff
	if !strings.Contains(b, `class="ln del"`) || !strings.Contains(b, `class="ln add"`) || !strings.Contains(b, "Data loss.") {
		t.Fatalf("diff missing:\n%s", b)
	}
	// filters: content only has no workflow events; status only has no commits
	if c := e.do(t, "bob", "GET", fshort+"/history?show=content", nil, nil).Body.String(); strings.Contains(c, ">submit") || !strings.Contains(c, "edited Impact") {
		t.Fatalf("content filter:\n%s", c)
	}
	if s := e.do(t, "bob", "GET", fshort+"/history?show=status", nil, nil).Body.String(); strings.Contains(s, "edited Impact") {
		t.Fatalf("status filter:\n%s", s)
	}
	full := e.do(t, "bob", "GET", fshort+"/history?ev="+newest+"&view=full", nil, nil).Body.String()
	if strings.Contains(full, `class="ln del"`) || !strings.Contains(full, "Data loss.") {
		t.Fatalf("full text:\n%s", full)
	}
	// a reviewer can't restore; the author can (while she may edit)
	if strings.Contains(b, "/history/restore") {
		t.Fatal("reviewer sees Restore")
	}
	if rec := e.do(t, "bob", "POST", fshort+"/history/restore", url.Values{"ev": {newest}, "section": {"Impact"}}, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("reviewer restore %d", rec.Code)
	}
	if err := st.Transition("acme", fdir, workflow.Return, "add PoC", wBob); err != nil {
		t.Fatal(err)
	}
	ab := e.do(t, "alice", "GET", fshort+"/history", nil, nil).Body.String()
	if !strings.Contains(ab, "/history/restore") {
		t.Fatalf("author lacks Restore:\n%s", ab)
	}
	// restore the first edit of Impact
	older := ""
	for _, m := range evRe.FindAllStringSubmatch(ab, -1) {
		pg := e.do(t, "alice", "GET", fshort+"/history?ev="+m[1], nil, nil).Body.String()
		if strings.Contains(pg, "Read the user table.") && !strings.Contains(pg, "Data loss.") {
			older = m[1]
			break
		}
	}
	if older == "" {
		t.Fatal("no version with the first text")
	}
	ref, _ := st.Finding("acme", fdir)
	cur, _ := ref.F.Section("Impact")
	rec = e.do(t, "alice", "POST", fshort+"/history/restore", url.Values{"ev": {older}, "section": {"Impact"}, "base": {store.BodyHash(cur)}}, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("restore %d %s", rec.Code, rec.Body.String())
	}
	ref, _ = st.Finding("acme", fdir)
	if body, _ := ref.F.Section("Impact"); strings.TrimSpace(body) != "Read the user table." {
		t.Fatalf("restored %q", body)
	}
	// a stale base is a conflict
	if rec := e.do(t, "alice", "POST", fshort+"/history/restore", url.Values{"ev": {older}, "section": {"Impact"}, "base": {store.BodyHash(cur)}}, nil); rec.Code != http.StatusConflict {
		t.Fatalf("stale restore %d", rec.Code)
	}
	if rec := e.do(t, "alice", "GET", fshort+"/history?ev=0000000000000000000000000000000000000000", nil, nil); rec.Code != 200 {
		t.Fatalf("unknown event %d", rec.Code)
	}
}

// Restore replaces the section's text, so its button asks first (the page's
// own dialog, data-confirm); a viewer who cannot restore has the empty slot.
func TestHistoryRestoreAsks(t *testing.T) {
	e := setup(t)
	if err := e.srv.Store.UpdateSection("acme", fdir, "Impact", "Read the user table.", "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	ab := e.do(t, "alice", "GET", fshort+"/history", nil, nil).Body.String()
	if !strings.Contains(ab, `<button class="btn secondary sm w96" data-confirm="Restore Impact?">Restore</button>`) {
		t.Fatalf("Restore does not ask:\n%s", between(ab, `class="dhead flush"`, `class="lines flush"`))
	}
	bb := e.do(t, "bob", "GET", fshort+"/history", nil, nil).Body.String()
	if strings.Contains(bb, `data-confirm="Restore`) || !strings.Contains(bb, `<span class="slot w96"></span>`) {
		t.Fatalf("a viewer who cannot restore:\n%s", between(bb, `class="dhead flush"`, `class="lines flush"`))
	}
}

// The history is read from git once per engagement HEAD.
func TestHistoryCachedPerHead(t *testing.T) {
	e := setupSerial(t) // counts git processes
	e.do(t, "alice", "GET", fshort+"/history", nil, nil)
	n := gitrepo.Spawned()
	e.do(t, "alice", "GET", fshort+"/history", nil, nil)
	if gitrepo.Spawned() != n {
		t.Fatal("second view started git")
	}
	e.srv.Store.UpdateSection("acme", fdir, "Impact", "x", "", e.authorOf(wAlice))
	n = gitrepo.Spawned()
	if b := e.do(t, "alice", "GET", fshort+"/history", nil, nil).Body.String(); gitrepo.Spawned() == n || !strings.Contains(b, "edited Impact") {
		t.Fatalf("new commit not read:\n%s", b)
	}
}

// History names the front matter part a version changed: a title edit is
// "edited the title", not "edited details".
func TestHistoryNamesFrontMatterPart(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	alice := e.authorOf(config.User{Username: "alice", Role: "pentester"})
	if err := st.UpdateTitle("acme", "F-001-sql-injection", "Blind SQL injection", alice); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSeverity("acme", "F-001-sql-injection", "high", "", alice); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", "/e/acme/f/001/history", nil, nil).Body.String()
	for _, want := range []string{"edited the title", "edited severity"} {
		if !strings.Contains(b, want) {
			t.Errorf("history lacks %q", want)
		}
	}
	if strings.Contains(b, "edited details") {
		t.Error("a title or severity edit labelled \"edited details\"")
	}
}
