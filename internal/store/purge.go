package store

import (
	"errors"
	"fmt"
	"log"

	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/workflow"
)

// ErrPurgeIncomplete: the history was rewritten (the purge happened), but a
// step after it failed: git's cleanup, the mark, the audit entry or the
// main repository's pointer. Purging again finishes what can be finished.
var ErrPurgeIncomplete = errors.New("purged from history, but not finished")

// PurgeFromHistory removes every earlier version of an attachment from the
// engagement's git history (D28: the original of a redacted image).
// Directors only; not on an archived engagement. It runs under the
// engagement's lock, so a push is wholly before or after it. A failure
// before git's gc puts the repository back as it was; once gc ran there is
// no way back, so the purge is recorded and the error says the cleanup
// failed. The removed blobs are remembered, so a push from an older clone
// cannot bring them back.
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
	p := "findings/" + ref.Dir + "/attachments/" + name
	keep, err := r.BlobAt("HEAD", p)
	if err != nil {
		return err
	}
	if keep == "" {
		return ErrNotFound
	}
	all, err := r.BlobsOf(p)
	if err != nil {
		return err
	}
	var old []string
	for _, b := range all {
		if b != keep {
			old = append(old, b)
		}
	}
	if len(old) == 0 {
		// nothing earlier in history (or purged before, and that purge did
		// not finish): its cleanup runs again while an original it removed
		// is still on disk; then the mark goes, and the main repo's pointer
		// follows
		if err := s.finishCleanup(r, engID, name); err != nil {
			return fmt.Errorf("%w: %w", ErrPurgeIncomplete, err)
		}
		if err := errors.Join(s.db.MarkPurged(engID, fid, name, nil), s.SyncPointers()); err != nil {
			return fmt.Errorf("%w: %w", ErrPurgeIncomplete, err)
		}
		s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeContent})
		return nil
	}
	head0, err := gitrepo.ReadHead(r.Dir)
	if err != nil {
		return err
	}
	// the ids are remembered first: once the history is rewritten nothing
	// may lose them, or a push from an old clone brings the original back
	added, err := s.db.AddPurgedBlobs(engID, name, old)
	if err != nil {
		return err
	}
	err = r.DropOldBlobsWith(p, keep, s.beforePurgeGC)
	if err != nil && !errors.Is(err, gitrepo.ErrPurgeCleanup) {
		// put back only what moved: git refuses a rewrite of a dirty work
		// tree, and a reset would throw that change away
		if h, herr := gitrepo.ReadHead(r.Dir); herr != nil || h != head0 {
			if rerr := r.ResetTo(head0); rerr != nil {
				return fmt.Errorf("%w; and putting %s back: %v", err, head0, rerr) // the ids stay: the rewrite may stand
			}
		}
		s.Invalidate(engID)
		if derr := s.db.DropPurgedBlobs(engID, added); derr != nil {
			log.Printf("purge %s %s: forgetting the blob ids: %v", engID, p, derr)
		}
		return err
	}
	// rewritten (and perhaps not cleaned up): record it all; the mark goes
	// once the originals are off the disk too (Purge again runs gc)
	s.Invalidate(engID)
	errs := []error{err}
	if err == nil {
		errs = append(errs, s.db.MarkPurged(engID, fid, name, nil))
	}
	errs = append(errs, s.db.Audit(u.Username, "attachment.purge", engID+"/"+fid+"/"+name, fmt.Sprintf("%d earlier versions", len(old))))
	// the main repo's pointer follows the new history (engagement, then main)
	errs = append(errs, s.SyncPointers())
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeContent})
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%w: %w", ErrPurgeIncomplete, err)
	}
	return nil
}

// finishCleanup runs git's gc again when a blob purged for name is still on
// disk (a purge whose gc failed before it removed anything).
func (s *Store) finishCleanup(r *gitrepo.Repo, engID, name string) error {
	purged, err := s.db.PurgedBlobs(engID)
	if err != nil {
		return err
	}
	for b, n := range purged {
		if n == name && r.HasObject(b) {
			if err := r.GC(); err != nil {
				return fmt.Errorf("%w: %v", gitrepo.ErrPurgeCleanup, err)
			}
			return nil
		}
	}
	return nil
}
