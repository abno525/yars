package web

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var atabRe = regexp.MustCompile(`<a class="atab[^"]*" href="([^"]+)">([^<]+)</a>`)

// Admin › Engagements is gone: its address goes to the engagements list,
// Health is the System tab, and the tab bar is the same on every admin page.
func TestAdminTabsNoEngagements(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/admin/engagements", "/admin/engagements?show=archived"} {
		rec := e.do(t, "dora", "GET", p, nil, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/engagements" {
			t.Fatalf("GET %s: %d %q", p, rec.Code, rec.Header().Get("Location"))
		}
	}
	if rec := e.do(t, "dora", "GET", "/admin/health", nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/system" {
		t.Fatalf("GET /admin/health: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	for _, p := range []string{"/admin/engagements", "/admin/engagements/acme/archive", "/admin/engagements/acme/team"} {
		if rec := e.do(t, "dora", "POST", p, nil, nil); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s still answers %d", p, rec.Code)
		}
	}
	if e.srv.Store.Archived("acme") {
		t.Fatal("the old archive route still archives")
	}
	if rec := e.do(t, "alice", "GET", "/engagements", nil, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `class="table englist`) {
		t.Fatalf("GET /engagements: %d", rec.Code)
	}
	e.rules(t, styleRules, nil)
	// Users, Rules and Tokens carry their counts, as on the board
	nr := strconv.Itoa(len(e.srv.Rules.Rules().Rules))
	want := "Users · 4 /admin/users|Rules · " + nr + " /admin/rules|Structure /admin/structure|AI /admin/ai|System /admin/system|Activity /admin/activity|Tokens · 0 /admin/tokens"
	for _, p := range []string{"/admin/users", "/admin/rules", "/admin/structure", "/admin/ai", "/admin/system", "/admin/activity", "/admin/tokens", "/admin/webhooks"} {
		b := e.do(t, "dora", "GET", p, nil, nil).Body.String()
		var got []string
		for _, m := range atabRe.FindAllStringSubmatch(between(b, `class="atabs"`, "</nav>"), -1) {
			got = append(got, m[2]+" "+m[1])
		}
		if strings.Join(got, "|") != want {
			t.Fatalf("%s tabs:\n%s", p, strings.Join(got, "|"))
		}
	}
	b := e.do(t, "dora", "GET", "/admin/system", nil, nil).Body.String()
	if !strings.Contains(b, `<a class="atab on" href="/admin/system">System</a>`) {
		t.Fatal("System tab not on")
	}
	// Tokens is its own page, its tab on
	b = e.do(t, "dora", "GET", "/admin/tokens", nil, nil).Body.String()
	if !strings.Contains(b, `<a class="atab on" href="/admin/tokens">Tokens · 0</a>`) || strings.Contains(b, `<a class="atab on" href="/admin/activity"`) || !strings.Contains(b, `class="table stable tokentable"`) {
		t.Fatalf("tokens page:\n%s", between(b, `class="atabs"`, "</nav>"))
	}
	if rec := e.do(t, "alice", "GET", "/admin/tokens", nil, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("tokens page for a non-admin %d", rec.Code)
	}
}

// A red dot marks the Rules tab while a rule doesn't load and the System
// tab while the last health check found an error; no check runs for it.
func TestAdminTabDots(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: bad-level\n  target: title\n  regex_forbid: x\n  level: critical\n", nil)
	b := e.do(t, "dora", "GET", "/admin/users", nil, nil).Body.String()
	tabs := between(b, `class="atabs"`, "</nav>")
	if !strings.Contains(tabs, `href="/admin/rules">Rules · 0<span class="adot" title="1 invalid"></span></a>`) {
		t.Fatalf("rules dot:\n%s", tabs)
	}
	if strings.Contains(between(tabs, `href="/admin/system"`, "</a>"), "adot") || e.srv.healthRuns.Load() != 0 {
		t.Fatalf("system dot before any check (runs %d):\n%s", e.srv.healthRuns.Load(), tabs)
	}
	e.do(t, "dora", "POST", "/admin/system/check", nil, nil) // the invalid rule is an error
	tabs = between(e.do(t, "dora", "GET", "/admin/users", nil, nil).Body.String(), `class="atabs"`, "</nav>")
	if !strings.Contains(tabs, `href="/admin/system">System<span class="adot" title="1 error"></span></a>`) {
		t.Fatalf("system dot:\n%s", tabs)
	}
}
