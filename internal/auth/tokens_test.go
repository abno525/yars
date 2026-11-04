package auth

import (
	"strings"
	"testing"

	"yars/internal/config"
)

func TestTokens(t *testing.T) {
	d := newDB(t)
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	tk := NewTokens(d)
	tok, err := tk.Add("bob")
	if err != nil || !strings.HasPrefix(tok, "yars_") || len(tok) < 40 {
		t.Fatalf("token %q %v", tok, err)
	}
	if u, ok := tk.User(tok); !ok || u != "bob" {
		t.Fatalf("verify %q %v", u, ok)
	}
	if _, ok := tk.User(tok + "x"); ok {
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
	if err := NewTokens(d).Revoke("bob"); err != nil {
		t.Fatal(err)
	}
	if _, ok := tk.User(tok); ok {
		t.Fatal("revoked token accepted")
	}
}
