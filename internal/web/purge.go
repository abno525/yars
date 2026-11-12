package web

import (
	"errors"
	"net/http"

	"yars/internal/auth"
	"yars/internal/store"
)

// purgeView is the Purge from history confirm page (D28).
type purgeView struct {
	ID, Name, URL, Back string
	Error               string
}

// canPurge: a director, in an engagement that is not archived (the store's
// own rule; a withdrawn finding's files can be purged too).
func (s *Server) canPurge(r *http.Request, ref store.FindingRef) bool {
	return canManage(auth.UserFrom(r.Context())) && !s.Store.Archived(ref.EngID)
}

func purgeURL(ref store.FindingRef, name string) string {
	return findingURL(ref.EngID, ref.Dir) + "/attachments/" + name + "/purge"
}

func (s *Server) renderPurge(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	p, err := s.base(r, r.PathValue("eng"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if p.Finding, err = s.Store.Finding(p.Eng.ID, r.PathValue("fid")); err != nil {
		s.fail(w, err)
		return
	}
	ref := p.Finding
	if !s.canPurge(r, ref) {
		http.Error(w, "only a director can purge an image from history", http.StatusForbidden)
		return
	}
	name := r.PathValue("name")
	if !s.hasAttachment(ref, name) {
		http.NotFound(w, r)
		return
	}
	fu := findingURL(ref.EngID, ref.Dir)
	p.Purge = purgeView{ID: ref.F.Meta.ID, Name: name, URL: purgeURL(ref, name), Back: fu + "#attachments", Error: errMsg}
	p.TabTitle = "Purge " + name
	s.renderStatus(w, status, "purge.html", p)
}

// hasAttachment: the finding has a file of that name.
func (s *Server) hasAttachment(ref store.FindingRef, name string) bool {
	as, err := s.Store.AttachmentsOf(ref)
	if err != nil {
		return false
	}
	for _, a := range as {
		if a.Name == name {
			return true
		}
	}
	return false
}

func (s *Server) purgePage(w http.ResponseWriter, r *http.Request) {
	s.renderPurge(w, r, http.StatusOK, "")
}

func (s *Server) purgePost(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	if !s.canPurge(r, ref) {
		http.Error(w, "only a director can purge an image from history", http.StatusForbidden)
		return
	}
	err := s.Store.PurgeFromHistory(ref.EngID, ref.Dir, r.PathValue("name"), auth.UserFrom(r.Context()))
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrArchived):
		s.fail(w, err)
		return
	case err != nil:
		// the store put the repository back; the director can try again
		s.renderPurge(w, r, http.StatusInternalServerError, err.Error())
		return
	}
	http.Redirect(w, r, findingURL(ref.EngID, ref.Dir)+"#attachments", http.StatusSeeOther)
}
