package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"yars/internal/config"
	"yars/internal/db"
)

// Tokens are per-user API tokens for the MCP endpoint (Bearer) and git over
// HTTP (Basic, as the password). Each has a kind, scopes, an optional
// engagement list and expiry. Only their sha256 and last four characters are
// stored; the database is shared with the CLI, so a revoke takes effect at
// once.
type Tokens struct {
	db  *db.DB
	now func() time.Time
}

func NewTokens(d *db.DB) *Tokens { return &Tokens{db: d, now: time.Now} }

// Create makes a token for user as actor, stores its hash and returns the
// secret (shown once) with what was stored.
func (t *Tokens) Create(actor, user string, spec db.TokenSpec) (string, db.TokenInfo, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", db.TokenInfo{}, err
	}
	tok := "yars_" + hex.EncodeToString(b)
	h := hashSecret(tok)
	if _, err := t.db.CreateToken(user, h, tok[len(tok)-4:], spec); err != nil {
		return "", db.TokenInfo{}, err
	}
	info, _, err := t.db.TokenByHash(h)
	if err != nil {
		return "", db.TokenInfo{}, err
	}
	t.db.Audit(actor, "token.create", user, fmt.Sprintf("#%d %s %s %s", info.ID, info.Kind, strings.Join(info.Scopes, ","), info.Name))
	return tok, info, nil
}

// Add creates a token with every right for the MCP endpoint (yars token add).
func (t *Tokens) Add(user string) (string, error) {
	tok, _, err := t.Create("cli", user, db.TokenSpec{Kind: db.TokenMCP, Scopes: []string{db.ScopeAll}})
	return tok, err
}

// Verify returns the active account behind token and what the token may
// do. It fails for a token of another kind, an expired one, or one of a
// disabled or deleted account, or of one that must set a new password
// first (after an admin's reset: nothing else until then). The lookup is by hash, so the stored value
// never meets the presented one in a timing-sensitive comparison. The last
// use is recorded (at most once a minute).
func (t *Tokens) Verify(token, kind string) (config.User, db.TokenInfo, bool) {
	u, info, err := t.Lookup(token, kind)
	return u, info, err == nil
}

// Lookup is Verify with the reason of a refusal: ErrMustChange for a good
// token of an account that must set a new password first (it is told so;
// the token's info comes back, its account does not), ErrRefused for
// everything else.
func (t *Tokens) Lookup(token, kind string) (config.User, db.TokenInfo, error) {
	info, ok, err := t.db.TokenByHash(hashSecret(token))
	if err != nil || !ok || info.Kind != kind || !info.Valid(t.now()) {
		return config.User{}, db.TokenInfo{}, ErrRefused
	}
	u, ok, err := t.db.User(info.User)
	if err != nil || !ok || u.Disabled {
		return config.User{}, db.TokenInfo{}, ErrRefused
	}
	if u.MustChange {
		// the token is told apart (git checks it is the named account's)
		return config.User{}, info, ErrMustChange
	}
	t.db.TokenUsed(info.ID)
	return u, info, nil
}

// Revoke removes every token of user.
func (t *Tokens) Revoke(actor, user string) error {
	if err := t.db.RevokeTokens(user); err != nil {
		return err
	}
	return t.db.Audit(actor, "token.revoke", user, "all")
}

// RevokeID removes token id; owner "" revokes anyone's (admins), otherwise
// only a token of owner.
func (t *Tokens) RevokeID(actor string, id int64, owner string) error {
	if err := t.db.RevokeToken(id, owner); err != nil {
		return err
	}
	return t.db.Audit(actor, "token.revoke", owner, fmt.Sprintf("#%d", id))
}

// List returns every token.
func (t *Tokens) List() []db.TokenInfo {
	l, _ := t.db.Tokens()
	return l
}

// ListFor returns user's tokens.
func (t *Tokens) ListFor(user string) []db.TokenInfo {
	l, _ := t.db.UserTokens(user)
	return l
}
