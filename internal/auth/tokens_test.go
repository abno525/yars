package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The server's token set picks up `yars token add/revoke` run from another
// process without a restart (a lost laptop must be revocable at once).
func TestTokensReloadOnChange(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".yars"), 0o755)
	server, _ := LoadTokens(dir)
	cli, _ := LoadTokens(dir)
	tok, _ := cli.Add(dir, "alice")
	if u, ok := server.User(tok); !ok || u != "alice" {
		t.Fatal("new token not picked up")
	}
	cli2, _ := LoadTokens(dir)
	cli2.Revoke(dir, "alice")
	if _, ok := server.User(tok); ok {
		t.Fatal("revoked token still accepted by the running server")
	}
}

func TestTokens(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".yars"), 0o755)
	tk, err := LoadTokens(dir)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := tk.Add(dir, "bob")
	if err != nil || !strings.HasPrefix(tok, "yars_") || len(tok) < 40 {
		t.Fatalf("token %q %v", tok, err)
	}
	if u, ok := tk.User(tok); !ok || u != "bob" {
		t.Fatalf("verify %q %v", u, ok)
	}
	if _, ok := tk.User(tok + "x"); ok {
		t.Fatal("wrong token accepted")
	}
	info, _ := os.Stat(TokensPath(dir))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
	b, _ := os.ReadFile(TokensPath(dir))
	if strings.Contains(string(b), tok) {
		t.Fatal("plain token stored")
	}
	reloaded, _ := LoadTokens(dir)
	if u, ok := reloaded.User(tok); !ok || u != "bob" {
		t.Fatal("not persisted")
	}
	if len(reloaded.List()) != 1 || reloaded.List()[0].User != "bob" {
		t.Fatalf("list %+v", reloaded.List())
	}
	if err := reloaded.Revoke(dir, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.User(tok); ok {
		t.Fatal("revoked token accepted")
	}
}
