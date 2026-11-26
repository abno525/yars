package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
)

const maxBody = 2 << 20

type tokenKey struct{}

// WithToken attaches the API token a request came with, so each tool call
// is checked against its scopes and engagements.
func WithToken(ctx context.Context, t db.TokenInfo) context.Context {
	return context.WithValue(ctx, tokenKey{}, t)
}

func tokenFrom(ctx context.Context) (db.TokenInfo, bool) {
	t, ok := ctx.Value(tokenKey{}).(db.TokenInfo)
	return t, ok
}

// bearer is the token of an Authorization value: the scheme word "Bearer"
// in any case (R2), one or more spaces, then the token.
func bearer(h string) (string, bool) {
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	return strings.TrimLeft(rest, " "), true
}

// HTTPHandler serves MCP over HTTP (POST, JSON responses) for holders of a
// YARS MCP token of an active account. No cookies are accepted, so it is not
// exposed to CSRF.
func (s *Server) HTTPHandler(tokens *auth.Tokens) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		tok, ok := bearer(r.Header.Get("Authorization"))
		var user config.User
		var info db.TokenInfo
		err := auth.ErrRefused
		if ok {
			user, info, err = tokens.Lookup(strings.TrimSpace(tok), db.TokenMCP)
		}
		if errors.Is(err, auth.ErrMustChange) {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="yars"`)
			http.Error(w, "a valid YARS MCP token is required", http.StatusUnauthorized)
			return
		}
		// MCP 2025-06-18: a version the server does not speak is refused
		if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !slices.Contains(protocols, v) {
			http.Error(w, "unsupported MCP-Protocol-Version "+v+"; this server speaks "+strings.Join(protocols, ", "), http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := s.Handle(WithToken(r.Context(), info), user, body)
		if resp == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// an error with id null answers input the server could not accept
		// (not JSON, a batch, an invalid notification): MCP wants an HTTP
		// error status for it
		var a struct {
			ID    json.RawMessage `json:"id"`
			Error *rpcErr         `json:"error"`
		}
		if json.Unmarshal(resp, &a) == nil && a.Error != nil && string(a.ID) == "null" {
			w.WriteHeader(http.StatusBadRequest)
		}
		w.Write(resp)
	})
}
