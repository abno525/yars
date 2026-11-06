package web

import (
	"net/http"
	"regexp"
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
	want := "Users /admin/users|Rules /admin/rules|Structure /admin/structure|AI /admin/ai|System /admin/system|Activity /admin/activity|Tokens /admin/activity#tokens"
	for _, p := range []string{"/admin/users", "/admin/rules", "/admin/structure", "/admin/ai", "/admin/system", "/admin/activity", "/admin/webhooks"} {
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
}
