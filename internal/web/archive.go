package web

import (
	"net/http"

	"yars/internal/auth"
)

// archiveView is the read-only bar of an archived engagement: its ID, the
// Archived tag, when and by whom; directors get Reopen.
type archiveView struct {
	On         bool
	ID, At, By string
	CanReopen  bool
}

func (s *Server) archiveOf(eng string, director bool) archiveView {
	m, _ := s.Store.EngMeta(eng)
	return archiveView{On: true, ID: eng, At: day(m.ArchivedAt), By: m.ArchivedBy, CanReopen: director}
}

// engReopen opens an archived engagement for changes again (directors).
func (s *Server) engReopen(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	if err := s.Store.Unarchive(eng, auth.UserFrom(r.Context())); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/e/"+eng, http.StatusSeeOther)
}
