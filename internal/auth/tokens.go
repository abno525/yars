package auth

import (
	"crypto/rand"
	"encoding/hex"

	"yars/internal/db"
)

// Tokens are per-user API tokens for the MCP HTTP endpoint. Only their
// sha256 is stored; the database is shared with the CLI, so `yars token
// revoke` takes effect at once.
type Tokens struct{ db *db.DB }

func NewTokens(d *db.DB) *Tokens { return &Tokens{db: d} }

// Add creates a token for user, stores its hash and returns the token.
func (t *Tokens) Add(user string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := "yars_" + hex.EncodeToString(b)
	return tok, t.db.AddToken(user, hashSecret(tok))
}

// Revoke removes every token of user.
func (t *Tokens) Revoke(user string) error { return t.db.RevokeTokens(user) }

// User returns the owner of token. The lookup is by hash, so the stored
// value never meets the presented one in a timing-sensitive comparison.
func (t *Tokens) User(token string) (string, bool) {
	u, ok, _ := t.db.TokenUser(hashSecret(token))
	return u, ok
}

func (t *Tokens) List() []db.TokenInfo {
	l, _ := t.db.Tokens()
	return l
}
