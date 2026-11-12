package web

import (
	"errors"
	"net/http"
	"strings"

	"yars/internal/auth"
	"yars/internal/store"
)

// checksFix starts Fix with AI (M31, R7): the AI fixes the finding's open
// check results in the background and answers their threads. It answers
// the workflow bar and the strip, as Check does. Busy (a check or a fix
// runs) is 409, no right to edit 403, nothing to fix or no provider 400 with
// the store's words.
func (s *Server) checksFix(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	if s.Rules == nil {
		http.NotFound(w, r)
		return
	}
	err := s.Store.StartFix(ref.EngID, ref.Dir, auth.UserFrom(r.Context()))
	if errors.Is(err, store.ErrInvalidValue) {
		http.Error(w, strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": "), http.StatusBadRequest)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.checksStarted(w, r, ref)
}
