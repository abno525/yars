package web

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"yars/internal/auth"
	"yars/internal/gitrepo"
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

// purgeDenied answers a request canPurge refuses, naming the reason.
func (s *Server) purgeDenied(w http.ResponseWriter, r *http.Request, ref store.FindingRef) bool {
	switch {
	case !canManage(auth.UserFrom(r.Context())):
		http.Error(w, "only a director can purge an image from history", http.StatusForbidden)
	case s.Store.Archived(ref.EngID):
		s.fail(w, store.ErrArchived)
	default:
		return false
	}
	return true
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
	if s.purgeDenied(w, r, ref) {
		return
	}
	name := r.PathValue("name")
	exists, marked, err := s.attachmentState(ref, name)
	if err != nil {
		s.fail(w, err)
		return
	}
	// the page is offered for a marked file (the rows with a Purge link);
	// drawn again after a POST, the mark may already be gone
	if !exists || (errMsg == "" && !marked) {
		http.NotFound(w, r)
		return
	}
	fu := findingURL(ref.EngID, ref.Dir)
	p.Purge = purgeView{ID: ref.F.Meta.ID, Name: name, URL: purgeURL(ref, name), Back: fu + "#attachments", Error: errMsg}
	p.TabTitle = "Purge " + name
	s.renderStatus(w, status, "purge.html", p)
}

// attachmentState: the finding has a file of that name, and its original
// is in history (marked).
func (s *Server) attachmentState(ref store.FindingRef, name string) (exists, marked bool, err error) {
	as, err := s.Store.AttachmentsOf(ref)
	if err != nil {
		return false, false, err
	}
	for _, a := range as {
		if a.Name == name {
			return true, a.HasOriginal, nil
		}
	}
	return false, false, nil
}

func (s *Server) purgePage(w http.ResponseWriter, r *http.Request) {
	s.renderPurge(w, r, http.StatusOK, "")
}

func (s *Server) purgePost(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	if s.purgeDenied(w, r, ref) {
		return
	}
	// a file the finding has (marked or not: a purge that did not finish
	// may have cleared the mark already; the store then finishes it)
	name := r.PathValue("name")
	if exists, _, err := s.attachmentState(ref, name); err != nil {
		s.fail(w, err)
		return
	} else if !exists {
		http.NotFound(w, r)
		return
	}
	// git rewrites the whole history (after waiting for a push to end):
	// longer than the server's write timeout allows
	clearDeadlines(w)
	err := s.Store.PurgeFromHistory(ref.EngID, ref.Dir, name, auth.UserFrom(r.Context()))
	var elsewhere *gitrepo.ElsewhereError
	switch {
	case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrArchived):
		s.fail(w, err)
		return
	case errors.As(err, &elsewhere):
		// nothing changed; the director redacts the copy first (the heading
		// names the file: the one-line slot keeps room for the copy's place)
		s.renderPurge(w, r, http.StatusConflict, "An earlier version is also at "+strings.TrimPrefix(elsewhere.At, "findings/")+"; redact it there first")
		return
	case errors.Is(err, store.ErrPurgeIncomplete):
		// the original is out of the history; what failed after it is for
		// the server's log, and a second Purge finishes it
		log.Printf("purge %s/%s/%s: %v", ref.EngID, ref.Dir, name, err)
		s.renderPurge(w, r, http.StatusInternalServerError, "Purged from history, but not finished (see the server log); Purge again to finish")
		return
	case err != nil:
		// before the history was rewritten (the store put the repository
		// back), or putting it back failed: logged as any server error
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, findingURL(ref.EngID, ref.Dir)+"#attachments", http.StatusSeeOther)
}
