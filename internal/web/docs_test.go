package web

import (
	"net/http"
	"strings"
	"testing"
)

func TestDeveloperDocs(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "alice", "GET", "/docs", nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/docs/mcp" {
		t.Fatalf("/docs %d %s", rec.Code, rec.Header().Get("Location"))
	}
	pages := map[string][]string{
		// the tool list comes from the MCP server's own definitions
		"mcp":      {"list_engagements", "start_check", "list_templates", "list_notifications", "Authorization: Bearer", "/mcp", "2025-06-18", "Required", "Optional"},
		"scripts":  {"10 s", "1 MB", "20", "stdin", "stdout", "quote", "target", "cvss_reasons", "Script exporters"},
		"git":      {"--recurse-submodules", "/git/e/acme", "/git/yars"},
		"config":   {"severities", "details_rows", "smtp", "password_env", "base_url"},
		"webhooks": {"finding.status_changed", "finding.created", "chat.posted", "export.sent", "check.finished", "X-YARS-Signature", "sha256="},
	}
	for name, wants := range pages {
		rec := e.do(t, "alice", "GET", "/docs/"+name, nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", name, rec.Code)
		}
		b := rec.Body.String()
		for _, w := range wants {
			if !strings.Contains(b, w) {
				t.Errorf("%s lacks %q", name, w)
			}
		}
		if strings.Contains(b, ` style="`) || strings.Contains(b, "<style") {
			t.Errorf("%s: inline style", name)
		}
		if strings.Count(b, "<table") != strings.Count(b, "<thead>") {
			t.Errorf("%s: a table without column headers", name)
		}
		// one active top-nav item, one active tab
		if n := strings.Count(b, `class="on"`) + strings.Count(b, ` on"`); n != 2 {
			t.Errorf("%s: %d active items", name, n)
		}
		if !strings.Contains(b, `href="/docs/`+name+`" class="dtab on"`) {
			t.Errorf("%s: its tab is not active", name)
		}
	}
	if rec := e.do(t, "alice", "GET", "/docs/nope", nil, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown page %d", rec.Code)
	}
	// linked from the settings and the admin pages
	if !strings.Contains(e.do(t, "alice", "GET", "/settings", nil, nil).Body.String(), `href="/docs"`) {
		t.Error("no link on settings")
	}
	if !strings.Contains(e.do(t, "dora", "GET", "/admin/users", nil, nil).Body.String(), `class="adminfoot"`) {
		t.Error("no link in the admin footer")
	}
	// rendered once, then from the cache
	e.do(t, "alice", "GET", "/docs/scripts", nil, nil)
	before := e.srv.md.Misses()
	e.do(t, "alice", "GET", "/docs/scripts", nil, nil)
	if e.srv.md.Misses() != before {
		t.Error("docs not cached")
	}
}
