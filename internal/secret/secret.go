// Package secret encrypts the secrets YARS keeps in its database (personal
// Confluence/Jira keys, the AI key) with AES-256-GCM. The key lives in
// <data>/.yars/secret.key (mode 0600, git-ignored, never pushed); it is
// created by yars init or on first use.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// KeyPath is where a data directory's key lives.
func KeyPath(dataDir string) string { return filepath.Join(dataDir, ".yars", "secret.key") }

// Box encrypts and decrypts with one key.
type Box struct{ aead cipher.AEAD }

var ErrBadCiphertext = errors.New("secret: cannot decrypt (wrong key or damaged value)")

// EnsureKey creates the data directory's key file when it doesn't exist.
func EnsureKey(dataDir string) error {
	p := KeyPath(dataDir)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil // created meanwhile
	}
	if err != nil {
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(k) + "\n"); err != nil {
		f.Close()
		os.Remove(p)
		return err
	}
	return f.Close()
}

// Open loads the data directory's key, creating it on first use.
func Open(dataDir string) (*Box, error) {
	if err := EnsureKey(dataDir); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(KeyPath(dataDir))
	if err != nil {
		return nil, err
	}
	k, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != 32 {
		return nil, fmt.Errorf("%s: not a 256-bit hex key", KeyPath(dataDir))
	}
	return New(k)
}

// New makes a Box from a 32-byte key.
func New(key []byte) (*Box, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	return &Box{aead: g}, nil
}

// Encrypt returns base64(nonce || ciphertext) with a fresh random nonce.
func (b *Box) Encrypt(plain string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := b.aead.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt reverses Encrypt; a value sealed with another key or changed in
// any way is refused.
func (b *Box) Decrypt(enc string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	n := b.aead.NonceSize()
	if err != nil || len(raw) < n+b.aead.Overhead() {
		return "", ErrBadCiphertext
	}
	plain, err := b.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", ErrBadCiphertext
	}
	return string(plain), nil
}
