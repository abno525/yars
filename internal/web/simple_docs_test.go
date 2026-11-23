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
