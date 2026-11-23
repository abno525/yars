package web

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// The developer page of the simple workflow lists the MCP tools as its
// server words them (the simple workflow's actions, no review steps or
// reviewers) and has no Assign reviewers token action; the standard page
// keeps both.
func TestSimpleDocsPage(t *testing.T) {
	e := setupSimple(t)
	rec := e.do(t, "ben", "GET", "/docs/mcp", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/docs/mcp %d", rec.Code)
	}
	b := rec.Body.String()
	tools := between(b, "tooltable", "</table>")
	if !strings.Contains(tools, "complete | reopen | report | unreport | revert | withdraw | revise") {
		t.Errorf("transition's actions:\n%s", tools)
	}
	if w := regexp.MustCompile(`\b(sign_off|submit|verification|reviewers?|directors?|roles?)\b`).FindString(tools); w != "" {
		t.Errorf("the tools say %q", w)
	}
	acts := between(b, "Token actions → tools", "</table>")
	if strings.Contains(acts, "Assign reviewers") || strings.Contains(acts, "set_field reviewers") || !strings.Contains(acts, ">Change status<") {
		t.Errorf("token actions:\n%s", acts)
	}
	// the standard page: the standard workflow's text and every token action
	sb := setup(t).do(t, "alice", "GET", "/docs/mcp", nil, nil).Body.String()
	if st := between(sb, "tooltable", "</table>"); !strings.Contains(st, "submit | return | clear | sign_off") {
		t.Errorf("standard tools:\n%s", st)
	}
	if sa := between(sb, "Token actions → tools", "</table>"); !strings.Contains(sa, ">Assign reviewers<") || !strings.Contains(sa, "<span>set_field reviewers</span>") {
		t.Errorf("standard token actions:\n%s", sa)
	}
}

// The developer docs tell of the simple workflow: the MCP page has its
// section, and a webhook's status change can carry the action complete.
func TestSimpleDocsText(t *testing.T) {
	e := setupSimple(t)
	mcpPage := e.do(t, "ben", "GET", "/docs/mcp", nil, nil).Body.String()
	sec := between(mcpPage, ">Simple workflow</h2>", "<h2")
	for _, w := range []string{"yars init --simple", "<code>complete</code>", "<code>workflow</code>", "not_allowed", "<code>set_field reviewers</code>"} {
		if !strings.Contains(sec, w) {
			t.Errorf("the MCP page's simple workflow lacks %q:\n%s", w, sec)
		}
	}
	hooks := e.do(t, "ben", "GET", "/docs/webhooks", nil, nil).Body.String()
	if row := between(hooks, "<td><code>finding.status_changed</code></td>", "</tr>"); !strings.Contains(row, "<code>complete</code>") || !strings.Contains(row, "<code>approve</code>") {
		t.Errorf("the status change row:\n%s", row)
	}
}
