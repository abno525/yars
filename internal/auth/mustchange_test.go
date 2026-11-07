package auth

import (
	"testing"

	"yars/internal/config"
	"yars/internal/db"
)

// D26: after an admin's reset nothing works with the account until its
// user sets a new password: neither the temporary password for git (Check)
// nor tokens made before (MCP and git). Login works, to set it.
func TestMustChangeRefusesTokensAndCheck(t *testing.T) {
	d := newDB(t)
	h, _ := HashPassword("old-password-1")
	d.AddUser(config.User{Username: "pen2", Role: "pentester", PasswordHash: h})
	tk := NewTokens(d)
	mcp, err := tk.Add("pen2")
	if err != nil {
		t.Fatal(err)
	}
	git, _, err := tk.Create("pen2", "pen2", db.TokenSpec{Kind: db.TokenGit, Scopes: []string{db.ScopeAll}})
	if err != nil {
		t.Fatal(err)
	}
	temp, _ := HashPassword("temporary-pw-1")
	if err := d.ResetPassword("pen2", temp); err != nil {
		t.Fatal(err)
	}
	a := New(d)
	if _, ok := a.Check("pen2", "temporary-pw-1"); ok {
		t.Fatal("git password auth with a temporary password")
	}
	if _, ok := a.Login("pen2", "temporary-pw-1"); !ok {
		t.Fatal("cannot log in to set a new password")
	}
	if _, _, ok := tk.Verify(mcp, db.TokenMCP); ok {
		t.Fatal("an MCP token works before the new password")
	}
	if _, _, ok := tk.Verify(git, db.TokenGit); ok {
		t.Fatal("a git token works before the new password")
	}
	nh, _ := HashPassword("new-password-1")
	if err := d.ChangePassword("pen2", nh); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := tk.Verify(mcp, db.TokenMCP); !ok {
		t.Fatal("the MCP token after the new password")
	}
	if _, ok := a.Check("pen2", "new-password-1"); !ok {
		t.Fatal("git auth after the new password")
	}
}
