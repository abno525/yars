package web

import (
	"net/http"
	"strings"
	"testing"

	"yars/internal/mcp"
)

func TestDeveloperDocs(t *testing.T) {
	e := setup(t)
	if rec := e.do(t, "alice", "GET", "/docs", nil, nil); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/docs/mcp" {
		t.Fatalf("/docs %d %s", rec.Code, rec.Header().Get("Location"))
	}
	pages := map[string][]string{
		// the tool list comes from the MCP server's own definitions
		"mcp":       {"list_engagements", "start_check", "list_templates", "list_notifications", "Authorization: Bearer", "/mcp", "2025-06-18", "Required", "Optional"},
		"rules":     {"Script rules", "10 s", "1 MB", "Hits per rule", "stdin", "stdout", "quote", "target", "cvss_reasons", "no_internal_hosts.py"},
		"exporters": {"Script exporters", "120 s", "100 MB", "html_sections", "csv_summary.py", "mark_reported"},
		"git":       {"--recurse-submodules", "/git/e/acme", "/git/yars"},
		"config":    {"severities", "details_rows", "smtp", "password_env", "base_url"},
		"webhooks":  {"finding.status_changed", "finding.created", "chat.posted", "export.sent", "check.finished", "X-YARS-Signature", "sha256="},
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
	// rules and exporters are separate tabs; each keeps to its own content
	rules := e.do(t, "alice", "GET", "/docs/rules", nil, nil).Body.String()
	exporters := e.do(t, "alice", "GET", "/docs/exporters", nil, nil).Body.String()
	if strings.Contains(rules, "120 s") || strings.Contains(rules, "csv_summary.py") {
		t.Error("rules tab shows exporter content")
	}
	if strings.Contains(exporters, "Hits per rule") || strings.Contains(exporters, "no_internal_hosts.py") {
		t.Error("exporters tab shows rule content")
	}
	for _, b := range []string{rules, exporters} {
		if !strings.Contains(b, `>Script rules</a>`) || !strings.Contains(b, `>Script exporters</a>`) || strings.Contains(b, `>Scripts</a>`) {
			t.Error("rail lacks the two script tabs")
		}
	}
	// the old single scripts page sends people to the rules tab
	if rec := e.do(t, "alice", "GET", "/docs/scripts", nil, nil); rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "/docs/rules" {
		t.Fatalf("/docs/scripts %d %s", rec.Code, rec.Header().Get("Location"))
	}
	// linked from the settings and the admin pages
	if !strings.Contains(e.do(t, "alice", "GET", "/settings", nil, nil).Body.String(), `href="/docs"`) {
		t.Error("no link on settings")
	}
	if !strings.Contains(e.do(t, "dora", "GET", "/admin/users", nil, nil).Body.String(), `class="adminfoot"`) {
		t.Error("no link in the admin footer")
	}
	// rendered once, then from the cache
	e.do(t, "alice", "GET", "/docs/rules", nil, nil)
	before := e.srv.md.Misses()
	e.do(t, "alice", "GET", "/docs/rules", nil, nil)
	if e.srv.md.Misses() != before {
		t.Error("docs not cached")
	}
}

// M32: the developer page lists every MCP tool with its token action (it is
// built from the catalogue, so a new tool shows without a template change).
func TestDocsListEveryTool(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/docs/mcp", nil, nil).Body.String()
	for _, td := range mcp.Catalog() {
		if !strings.Contains(b, td.Name) {
			t.Errorf("the docs page lacks %s", td.Name)
		}
	}
	if !strings.Contains(b, "a token needs run checks and edit findings") {
		t.Error("the docs page does not say fix_checks needs edit too")
	}
}

// With base_url set (behind a proxy), the docs show the public address,
// not the one the request came in on.
func TestDocsUseBaseURL(t *testing.T) {
	e := setup(t)
	c := e.srv.conf()
	c.BaseURL = "https://yars.example.com"
	e.srv.setConfig(c)
	if b := e.do(t, "alice", "GET", "/docs/mcp", nil, nil).Body.String(); !strings.Contains(b, "https://yars.example.com/mcp") {
		t.Error("mcp page lacks the public URL")
	}
	if b := e.do(t, "alice", "GET", "/docs/git", nil, nil).Body.String(); !strings.Contains(b, "https://alice@yars.example.com/git/yars") {
		t.Error("git page lacks the public URL")
	}
}
