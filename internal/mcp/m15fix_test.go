package mcp

import (
	"slices"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
)

// A disabled account can't be assigned as a reviewer.
func TestMCPDisabledNotReviewer(t *testing.T) {
	f := newFx(t)
	f.ok(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": "bob"})
	all := f.s.Users()
	f.s.Users = func() []config.User {
		us := slices.Clone(all)
		for i := range us {
			us[i].Disabled = us[i].Username == "bob"
		}
		return us
	}
	out, isErr := f.call(alice, "set_field", map[string]any{"engagement": "acme", "finding": "F-001", "field": "reviewers", "value": "bob"})
	if !isErr || !strings.Contains(out, "bob") {
		t.Fatalf("assigned a disabled account: %s", out)
	}
}

// lint_finding with all=true runs script and AI rules: it needs "checks".
func TestMCPLintAllNeedsChecks(t *testing.T) {
	f := newFx(t)
	read := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{db.ScopeRead}}
	a := map[string]any{"engagement": "acme", "finding": "F-001"}
	if out, isErr := f.callTok(alice, read, "lint_finding", a); isErr {
		t.Fatalf("fast lint with a read token: %s", out)
	}
	a["all"] = true
	if out, isErr := f.callTok(alice, read, "lint_finding", a); !isErr || !strings.Contains(out, "token") {
		t.Fatalf("lint all=true with a read token: %s", out)
	}
	checks := db.TokenInfo{Kind: db.TokenMCP, Scopes: []string{"checks"}}
	if out, isErr := f.callTok(alice, checks, "lint_finding", a); isErr {
		t.Fatalf("lint all=true with checks: %s", out)
	}
}
