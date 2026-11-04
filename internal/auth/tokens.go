package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// TokenInfo is a stored API token (only its hash is kept).
type TokenInfo struct {
	User    string `yaml:"user"`
	Hash    string `yaml:"sha256"`
	Created string `yaml:"created"`
}

// Tokens are per-user API tokens for the MCP HTTP endpoint, stored hashed in
// .yars/tokens.yaml (untracked, mode 0600).
type Tokens struct {
	mu      sync.Mutex
	entries []TokenInfo
	path    string
	stamp   string // size+mtime of the file when last read
}

func TokensPath(dataDir string) string { return filepath.Join(dataDir, ".yars", "tokens.yaml") }

func stampOf(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	return info.ModTime().String() + "/" + fmt.Sprint(info.Size())
}

func LoadTokens(dataDir string) (*Tokens, error) {
	t := &Tokens{path: TokensPath(dataDir)}
	return t, t.reload()
}

// reload re-reads the file; caller holds t.mu or owns t exclusively.
func (t *Tokens) reload() error {
	t.stamp = stampOf(t.path)
	b, err := os.ReadFile(t.path)
	if errors.Is(err, fs.ErrNotExist) {
		t.entries = nil
		return nil
	}
	if err != nil {
		return err
	}
	var es []TokenInfo
	if err := yaml.Unmarshal(b, &es); err != nil {
		return err
	}
	t.entries = es
	return nil
}

// fresh reloads the file when another process (yars token add/revoke)
// changed it, so revocation takes effect without a restart.
func (t *Tokens) fresh() {
	if t.path != "" && stampOf(t.path) != t.stamp {
		if err := t.reload(); err != nil {
			t.entries = nil // fail closed
		}
	}
}

func hashToken(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func (t *Tokens) save(dataDir string) error {
	b, err := yaml.Marshal(t.entries)
	if err != nil {
		return err
	}
	if err := os.WriteFile(TokensPath(dataDir), b, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(TokensPath(dataDir), 0o600); err != nil {
		return err
	}
	if t.path == TokensPath(dataDir) {
		t.stamp = stampOf(t.path)
	}
	return nil
}

// Add creates a token for user, stores its hash and returns the token.
func (t *Tokens) Add(dataDir, user string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := "yars_" + hex.EncodeToString(b)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fresh()
	t.entries = append(t.entries, TokenInfo{User: user, Hash: hashToken(tok), Created: time.Now().UTC().Format(time.RFC3339)})
	return tok, t.save(dataDir)
}

// Revoke removes every token of user.
func (t *Tokens) Revoke(dataDir, user string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fresh()
	var keep []TokenInfo
	for _, e := range t.entries {
		if e.User != user {
			keep = append(keep, e)
		}
	}
	t.entries = keep
	return t.save(dataDir)
}

// User returns the owner of token (constant-time comparison of hashes).
func (t *Tokens) User(token string) (string, bool) {
	h := []byte(hashToken(token))
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fresh()
	user, ok := "", false
	for _, e := range t.entries {
		if subtle.ConstantTimeCompare(h, []byte(e.Hash)) == 1 {
			user, ok = e.User, true
		}
	}
	return user, ok
}

func (t *Tokens) List() []TokenInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fresh()
	return append([]TokenInfo(nil), t.entries...)
}
