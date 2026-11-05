package web

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/store"
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
