package mcp

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"yars/internal/auth"
	"yars/internal/config"
)

const maxBody = 2 << 20

// HTTPHandler serves MCP over HTTP (POST, JSON responses) for holders of a
// YARS API token. No cookies are accepted, so it is not exposed to CSRF.
func (s *Server) HTTPHandler(tokens *auth.Tokens, user func(name string) (config.User, bool)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		var u config.User
		if ok {
			if name, found := tokens.User(strings.TrimSpace(tok)); found {
				u, ok = user(name)
			} else {
				ok = false
			}
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="yars"`)
			http.Error(w, "a valid YARS API token is required (yars token add <user>)", http.StatusUnauthorized)
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
		resp := s.Handle(r.Context(), u, body)
		if resp == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	})
}
