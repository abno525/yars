package policy

import (
	"testing"

	"yars/internal/db"
)

// A git token's scopes: a new finding (and its files) needs "create";
// changing or deleting anything that exists needs "edit".
func TestPolicyTokenScopes(t *testing.T) {
	f := newFx(t)
	add := newFinding("F-002-xss", "id: F-002\ntitle: XSS\nauthor: alice\n")
	modify := func(d string) {
		write(d, fdir+"/finding.md", "---\nid: F-001\ntitle: SQLi 2\nauthor: alice\n---\n\n## Description\n\ny\n")
	}
	attach := func(d string) { write(d, fdir+"/attachments/a.txt", "x") }

	f.c.Token = &db.TokenInfo{Scopes: []string{"create"}}
	if ps := f.push("alice", modify); !has(ps, "edit") {
		t.Fatalf("create-only token modified a finding: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", attach); !has(ps, "edit") {
		t.Fatalf("create-only token added to an existing finding: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", func(d string) {
		add(d)
		write(d, "findings/F-002-xss/attachments/a.txt", "x")
	}); len(ps) != 0 {
		t.Fatalf("create-only token can't add a finding: %v", ps)
	}

	f.c.Token = &db.TokenInfo{Scopes: []string{"edit"}}
	f.reclone()
	if ps := f.push("alice", newFinding("F-003-x", "id: F-003\ntitle: X\nauthor: alice\n")); !has(ps, "create") {
		t.Fatalf("edit-only token added a finding: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", modify); len(ps) != 0 {
		t.Fatalf("edit-only token can't edit: %v", ps)
	}

	f.c.Token = &db.TokenInfo{Scopes: []string{db.ScopeAll}}
	f.reclone()
	if ps := f.push("alice", newFinding("F-003-x", "id: F-003\ntitle: X\nauthor: alice\n")); len(ps) != 0 {
		t.Fatalf("full token: %v", ps)
	}
}

// TokenFromEnv reads the scopes the server hands the hook.
func TestParseTokenScopes(t *testing.T) {
	if tk := TokenFromEnv("", false); tk != nil {
		t.Fatal("password login got a token")
	}
	tk := TokenFromEnv("create,comment", true)
	if tk == nil || !tk.Allows("create") || tk.Allows("edit") {
		t.Fatalf("%+v", tk)
	}
	if tk := TokenFromEnv("", true); tk == nil || tk.Allows("edit") || tk.Allows("create") {
		t.Fatalf("empty scopes allow writes: %+v", tk)
	}
}
