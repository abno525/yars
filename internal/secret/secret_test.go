package secret

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := b.Encrypt("jira-key-1234")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(enc, "jira-key") {
		t.Fatalf("plain text in %q", enc)
	}
	if again, _ := b.Encrypt("jira-key-1234"); again == enc {
		t.Fatal("same ciphertext twice: nonce reused")
	}
	got, err := b.Decrypt(enc)
	if err != nil || got != "jira-key-1234" {
		t.Fatalf("decrypt %q %v", got, err)
	}
	// the key file is private and reused on the next open
	info, err := os.Stat(KeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", info.Mode().Perm())
	}
	b2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := b2.Decrypt(enc); err != nil || got != "jira-key-1234" {
		t.Fatalf("reopened: %q %v", got, err)
	}
}

func TestTamperAndWrongKey(t *testing.T) {
	b, _ := Open(t.TempDir())
	enc, _ := b.Encrypt("s3cret")
	bad := []byte(enc)
	bad[len(bad)-2] ^= 1
	if _, err := b.Decrypt(string(bad)); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	other, _ := Open(t.TempDir())
	if _, err := other.Decrypt(enc); err == nil {
		t.Fatal("decrypted with another key")
	}
	if _, err := b.Decrypt("not base64!"); err == nil {
		t.Fatal("garbage accepted")
	}
	if _, err := b.Decrypt(""); err == nil {
		t.Fatal("empty accepted")
	}
}

func TestBadKeyFile(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Dir(KeyPath(dir)), 0o755)
	os.WriteFile(KeyPath(dir), []byte("short"), 0o600)
	if _, err := Open(dir); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestEnsureKeyCreatesOnce(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureKey(dir); err != nil {
		t.Fatal(err)
	}
	k1, _ := os.ReadFile(KeyPath(dir))
	if err := EnsureKey(dir); err != nil {
		t.Fatal(err)
	}
	k2, _ := os.ReadFile(KeyPath(dir))
	if string(k1) != string(k2) || len(k1) == 0 {
		t.Fatal("key replaced")
	}
}
