package auth

import (
	"strings"
	"testing"
	"time"

	"yars/internal/config"
	"yars/internal/db"
)

// Admin › Activity shows a new token's actions as the other lists there
// read: "a, b". Its fields stand apart by " · ", as who · what in the inbox,
// or the name reads as one more action ("edit, comment laptop").
func TestTokenAuditScopesSpaced(t *testing.T) {
	d := newDB(t)
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	if _, _, err := NewTokens(d).Create("dora", "bob", db.TokenSpec{Name: "laptop", Kind: db.TokenMCP, Scopes: []string{"edit", "comment"}}); err != nil {
		t.Fatal(err)
	}
	if log, _ := d.AuditLog(1); len(log) != 1 || !strings.HasSuffix(log[0].Detail, " · mcp · edit, comment · laptop") {
		t.Fatalf("audit %+v", log)
	}
}

func TestTokens(t *testing.T) {
	d := newDB(t)
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	tk := NewTokens(d)
	tok, err := tk.Add("bob")
	if err != nil || !strings.HasPrefix(tok, "yars_") || len(tok) < 40 {
		t.Fatalf("token %q %v", tok, err)
	}
	if u, _, ok := tk.Verify(tok, db.TokenMCP); !ok || u.Username != "bob" {
		t.Fatalf("verify %q %v", u.Username, ok)
	}
	if _, _, ok := tk.Verify(tok+"x", db.TokenMCP); ok {
		t.Fatal("wrong token accepted")
	}
	var n int
	d.QueryRow("SELECT count(*) FROM tokens WHERE hash = ?", tok).Scan(&n)
	if n != 0 {
		t.Fatal("plain token stored")
	}
	if _, err := tk.Add("ghost"); err == nil {
		t.Fatal("token for an unknown account")
	}
	// another process (yars token revoke) shares the database: instant effect
	if l := NewTokens(d).List(); len(l) != 1 || l[0].User != "bob" {
		t.Fatalf("list %+v", l)
	}
	if err := NewTokens(d).Revoke("cli", "bob"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := tk.Verify(tok, db.TokenMCP); ok {
		t.Fatal("revoked token accepted")
	}
}

func TestScopedTokenVerify(t *testing.T) {
	d := newDB(t)
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	tk := NewTokens(d)
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	tk.now = func() time.Time { return now }
	sec, info, err := tk.Create("bob", "bob", db.TokenSpec{Name: "ci", Kind: db.TokenGit, Scopes: []string{db.ScopeRead},
		Expires: now.Add(time.Hour).Format(time.RFC3339)})
	if err != nil {
		t.Fatal(err)
	}
	if info.ID == 0 || info.Last4 != sec[len(sec)-4:] || info.Hash == sec {
		t.Fatalf("info %+v", info)
	}
	// a git token is not an MCP token and the other way round
	if _, _, ok := tk.Verify(sec, db.TokenMCP); ok {
		t.Fatal("git token accepted for MCP")
	}
	u, got, ok := tk.Verify(sec, db.TokenGit)
	if !ok || u.Username != "bob" || got.ID != info.ID || !got.ReadOnly() {
		t.Fatalf("verify %+v %+v %v", u, got, ok)
	}
	if l := tk.ListFor("bob"); len(l) != 1 || l[0].LastUsed == "" {
		t.Fatalf("last use not recorded: %+v", l)
	}
	// expired
	now = now.Add(2 * time.Hour)
	if _, _, ok := tk.Verify(sec, db.TokenGit); ok {
		t.Fatal("expired token accepted")
	}
	// disabled account
	now = now.Add(-2 * time.Hour)
	d.SetDisabled("bob", true)
	if _, _, ok := tk.Verify(sec, db.TokenGit); ok {
		t.Fatal("disabled account's token accepted")
	}
	d.SetDisabled("bob", false)
	// revoke by id: only the owner, or anyone with owner ""
	if err := tk.RevokeID("eve", info.ID, "eve"); err == nil {
		t.Fatal("revoked another account's token")
	}
	if err := tk.RevokeID("bob", info.ID, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := tk.Verify(sec, db.TokenGit); ok {
		t.Fatal("revoked token accepted")
	}
	log, _ := d.AuditLog(10)
	if len(log) != 2 || log[0].Action != "token.revoke" || log[1].Action != "token.create" || log[1].Actor != "bob" {
		t.Fatalf("audit %+v", log)
	}
}
