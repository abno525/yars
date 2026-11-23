package web

import (
	"net/http"
	"net/url"
	"strings"

	"yars/internal/auth"
	"yars/internal/store"
)

// engOf is the engagement a request is about: the {eng} of /e/{eng}/…, or
// the eng parameter of the event stream ("" = none).
func engOf(r *http.Request) string {
	if rest, ok := strings.CutPrefix(r.URL.EscapedPath(), "/e/"); ok {
		seg, _, _ := strings.Cut(rest, "/")
		if e, err := url.PathUnescape(seg); err == nil {
			return e
		}
		return seg
	}
	if r.URL.Path == "/events" {
		return r.URL.Query().Get("eng")
	}
	return ""
}

// teamGate answers 404 for an engagement the user is not on the team of
// (directors and admins see all), as if it did not exist.
func (s *Server) teamGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// an invalid id names no engagement: its handler rejects it as before
		if eng := engOf(r); store.ValidID(eng) && !s.Store.CanSee(auth.UserFrom(r.Context()), eng) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
