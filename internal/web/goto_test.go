package web

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/store"
)

func TestGoToSearch(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	a := e.authorOf(config.User{Username: "alice"})
	st.CreateFinding("acme", "Reflected XSS in search", a)
	st.CreateFinding("acme", "Stored injection in notes", a)
	// another team's engagement stays hidden
	st.CreateEngagement(store.Engagement{ID: "beta", Name: "Beta"}, a)
	st.CreateFinding("beta", "Injection in beta", a)

	get := func(user, q string) string {
		t.Helper()
		rec := e.do(t, user, "GET", "/go/search?q="+q, nil, map[string]string{"HX-Request": "true"})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %d", q, rec.Code)
		}
		return rec.Body.String()
	}
	b := get("alice", "injection")
	if !strings.Contains(b, `href="/e/acme/f/001"`) || !strings.Contains(b, `href="/e/acme/f/003"`) || strings.Contains(b, "beta") {
		t.Fatalf("title search %s", b)
	}
	if strings.Contains(b, "<html") {
		t.Fatal("full page for a fragment")
	}
	// by ID: the exact finding first
	b = get("alice", "F-002")
	if i := strings.Index(b, `href="/e/acme/f/002"`); i < 0 || strings.Contains(b, `href="/e/acme/f/001"`) {
		t.Fatalf("id search %s", b)
	}
	if b := get("alice", "2"); !strings.Contains(b, `href="/e/acme/f/002"`) {
		t.Fatalf("number search %s", b)
	}
	// a director sees every engagement
	if b := get("dora", "injection"); !strings.Contains(b, `href="/e/beta/f/001"`) {
		t.Fatalf("director %s", b)
	}
	if b := get("alice", ""); strings.Contains(b, "href=") {
		t.Fatal("results for an empty query")
	}
	// at most 20 rows
	for i := range 25 {
		st.CreateFinding("acme", fmt.Sprintf("Weak cipher %d", i), a)
	}
	if n := strings.Count(get("alice", "cipher"), `<a class="res`); n != 20 {
		t.Fatalf("%d rows", n)
	}
	// the header has the Go to button and the palette
	page := e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String()
	if !strings.Contains(page, `data-goto`) || !strings.Contains(page, `id="goto"`) || !strings.Contains(page, `hx-get="/go/search"`) {
		t.Fatal("no Go to in the header")
	}
}

// Go to keeps a 480px box for its results, so it does not grow as you type.
// Before anything is typed, and when nothing matches, the box shows the
// list's head and its one empty row (—), as an empty table does, not a
// blank box. Each result's "engagement · ID" is a 170px column (as on the
// inbox), the engagement ending in "…" past 96px, so the titles line up.
func TestGoToEmptyAndAligned(t *testing.T) {
	e := setup(t)
	get := func(q string) string {
		t.Helper()
		rec := e.do(t, "alice", "GET", "/go/search?q="+q, nil, map[string]string{"HX-Request": "true"})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %d", q, rec.Code)
		}
		return rec.Body.String()
	}
	none := `<div class="gh"><span>Findings</span><span class="mono">—</span></div><div class="resnone">—</div>`
	if box := between(e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(), `<div id="goto-results"`, "</div>\n"); !strings.Contains(box, none) {
		t.Errorf("Go to opens blank:\n%s", box)
	}
	if b := get(""); !strings.Contains(b, none) {
		t.Errorf("empty query:\n%s", b)
	}
	if b := get("zzzz"); !strings.Contains(b, `<span>Findings</span><span class="mono">0</span>`) || !strings.Contains(b, `<div class="resnone">—</div>`) || strings.Contains(b, "href=") {
		t.Errorf("no match:\n%s", b)
	}
	b := get("F-001")
	if !strings.Contains(b, `<span class="mono" title="acme · F-001"><span class="engid">acme</span> · F-001</span><span class="restitle">`) || strings.Contains(b, "resnone") {
		t.Errorf("a result:\n%s", b)
	}
	css := e.do(t, "alice", "GET", staticPrefix()+"/style.css", nil, nil).Body.String()
	if rule := between(css, "\n.resline .mono {", "}"); !strings.Contains(rule, "width: 170px; flex: none; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;") {
		t.Errorf(".resline .mono: %q", rule)
	}
	if rule := between(css, "\n.c-eng .engid, .resline .engid {", "}"); !strings.Contains(rule, "max-width: 96px;") {
		t.Errorf("engagement cap: %q", rule)
	}
	if rule := between(css, "\n.resnone {", "}"); !strings.Contains(rule, "min-height: 56px;") || !strings.Contains(rule, "color: var(--muted);") {
		t.Errorf(".resnone: %q", rule)
	}
}
