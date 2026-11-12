package store

import (
	"fmt"

	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/workflow"
)

// PurgeFromHistory removes every earlier version of an attachment from the
// engagement's git history (D28: the original of a redacted image).
// Directors only; not on an archived engagement. It runs under the
// engagement's lock, so a push is wholly before or after it; a failure
// half-way puts the repository back as it was. The removed blobs are
// remembered, so a push from an older clone cannot bring them back.
func (s *Store) PurgeFromHistory(engID, dir, name string, u config.User) error {
	if !workflow.AtLeast(u, "director") {
		return &workflow.Denied{Reason: "only a director can purge an image from history"}
	}
	if s.db == nil {
		return ErrNoDB
	}
	if !ValidID(engID) || !ValidID(dir) || !attachmentRe.MatchString("attachments/"+name) {
		return ErrNotFound
	}
	ref, err := s.Finding(engID, dir) // before the lock: it reads under it
	if err != nil {
		return err
	}
	fid := ref.F.Meta.ID
	unlock := s.LockEngagement(engID)
	defer unlock()
	if err := s.writable(engID); err != nil {
		return err
	}
	r, err := s.EngRepo(engID)
	if err != nil {
		return err
	}
	p := "findings/" + dir + "/attachments/" + name
	blobs, err := r.BlobsOf(p)
	if err != nil {
		return err
	}
	if len(blobs) == 0 {
		return ErrNotFound
	}
	if len(blobs) == 1 { // nothing earlier: only the mark goes
		return s.db.MarkPurged(engID, fid, name, nil)
	}
	head0, err := gitrepo.ReadHead(r.Dir)
	if err != nil {
		return err
	}
	if err := r.DropOldBlobsWith(p, blobs[0], s.beforePurgeGC); err != nil {
		if rerr := r.ResetTo(head0); rerr != nil {
			err = fmt.Errorf("%w; and putting %s back: %v", err, head0, rerr)
		}
		s.Invalidate(engID)
		return err
	}
	s.Invalidate(engID)
	if err := s.db.MarkPurged(engID, fid, name, blobs[1:]); err != nil {
		return err
	}
	if err := s.db.Audit(u.Username, "attachment.purge", engID+"/"+fid+"/"+name, fmt.Sprintf("%d earlier versions", len(blobs)-1)); err != nil {
		return err
	}
	// the main repo's pointer follows the new history (engagement, then main)
	if err := s.SyncPointers(); err != nil {
		return err
	}
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeContent})
	return nil
}
