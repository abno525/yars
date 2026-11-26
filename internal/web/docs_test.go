package web

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"yars/docs"
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
	// every tab has its page in the binary, so a new tab cannot be a 404
	for _, tab := range docsTabs {
		if !slices.Contains(docs.Pages, tab.Key) {
			t.Errorf("the %s tab has no embedded page", tab.Key)
		}
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
	// Developers itself opens from the user name only; the admin footer
	// links the admin's topics
	if b := e.do(t, "dora", "GET", "/admin/users", nil, nil).Body.String(); strings.Contains(b, ">Developers<") {
		t.Error("Developers linked outside Settings")
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
	// the token actions table lists fix_checks under Edit findings as well
	acts := between(b, "Token actions → tools", "</table>")
	edit := between(acts, ">Edit findings<", "</tr>")
	if !strings.Contains(edit, "<span>fix_checks</span>") || !strings.Contains(between(acts, ">Run checks<", "</tr>"), "<span>fix_checks</span>") {
		t.Errorf("token actions:\n%s", acts)
	}
}

// The tools table is a .table.stable, whose cells keep to one line
// (white-space: nowrap, which beats .tooltable td's normal): a parameter's
// row lets its name and description wrap, so a long description shows whole
// instead of being cut mid-word at its column's edge.
func TestDocsParamRowsWrap(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/docs/mcp", nil, nil).Body.String()
	if !strings.Contains(b, `<table class="table stable tooltable flush">`) || !strings.Contains(b, `<div class="prow"><span class="pn">`) {
		t.Fatalf("tools table:\n%s", between(b, "tooltable", "</table>"))
	}
	css := e.do(t, "alice", "GET", staticPrefix()+"/style.css", nil, nil).Body.String()
	if !strings.Contains(between(css, "\n.table.stable td {", "}"), "white-space: nowrap;") {
		t.Fatal("stable tables no longer keep their cells to one line; recheck the parameter rows")
	}
	if rule := between(css, "\n.prow {", "}"); !strings.Contains(rule, "white-space: normal;") {
		t.Errorf(".prow rule: %q", rule)
	}
	// a tool's description wraps too, and breaks inside text with no
	// spaces: set_field's JSON example was cut at the cell's edge (the final
	// test's browser check)
	if rule := between(css, "\n.toolcell .td {", "}"); !strings.Contains(rule, "white-space: normal; overflow-wrap: anywhere;") {
		t.Errorf(".toolcell .td rule: %q", rule)
	}
}

// A command line (Remote, Local, the git clones) wraps at its spaces, so
// "Bearer" stays whole; a word longer than the line still breaks, as in the
// other pre-wrapped text (overflow-wrap: anywhere, not word-break: break-all).
func TestDocsCommandsWrapAtSpaces(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/docs/mcp", nil, nil).Body.String()
	if !strings.Contains(b, `<div class="codeline"><code id="mcp-remote">`) {
		t.Fatalf("no Remote command line:\n%s", b)
	}
	css := e.do(t, "alice", "GET", staticPrefix()+"/style.css", nil, nil).Body.String()
	rule := between(css, "\n.codeline code {", "}")
	if strings.Contains(rule, "break-all") || !strings.Contains(rule, "white-space: pre-wrap; overflow-wrap: anywhere;") {
		t.Errorf(".codeline code rule: %q", rule)
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
