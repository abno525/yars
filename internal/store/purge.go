package store

import (
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"

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
	all, err := r.BlobsWhere(versionPaths(p, fid, name))
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
		if err := s.finishCleanup(r, engID); err != nil {
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
	err = r.DropOldBlobsWith(p, keep, old, s.beforePurgeGC)
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

// versionPaths matches the paths an attachment's versions have in its
// engagement's repository: p, and name under every folder name the finding
// fid has had (a push may rename it, before or after the redaction):
// "<id>" or "<id>-<slug>".
func versionPaths(p, fid, name string) func(string) bool {
	return func(q string) bool {
		seg := strings.Split(q, "/")
		return q == p || len(seg) == 4 && seg[0] == "findings" && (seg[1] == fid || strings.HasPrefix(seg[1], fid+"-")) &&
			seg[2] == "attachments" && seg[3] == name
	}
}

// RetestHolders lists the retest copies of the finding (those a redaction
// reaches) whose repository holds an earlier version of its attachment
// name, in its files or its history: one a Purge from history removes
// here, or removed. A purge is per engagement; a director purges there
// too (Q12).
func (s *Store) RetestHolders(engID, dir, name string) ([]FindingRef, error) {
	if !ValidID(engID) || !ValidID(dir) || !attachmentRe.MatchString("attachments/"+name) {
		return nil, ErrNotFound
	}
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return nil, err
	}
	fid := ref.F.Meta.ID
	r, err := s.EngRepo(engID)
	if err != nil {
		return nil, err
	}
	p := "findings/" + ref.Dir + "/attachments/" + name
	keep, err := r.BlobAt("HEAD", p)
	if err != nil {
		return nil, err
	}
	all, err := r.BlobsWhere(versionPaths(p, fid, name))
	if err != nil {
		return nil, err
	}
	old := map[string]bool{}
	for _, b := range all {
		old[b] = true
	}
	if s.db != nil { // the ones a purge here took out already
		purged, err := s.db.PurgedBlobs(engID)
		if err != nil {
			return nil, err
		}
		for b, n := range purged {
			if n == name {
				old[b] = true
			}
		}
	}
	delete(old, keep)
	if len(old) == 0 {
		return nil, nil
	}
	copies, err := s.retestCopies(engID, fid)
	if err != nil {
		return nil, err
	}
	var out []FindingRef
	for _, c := range copies {
		cr, err := s.EngRepo(c.EngID)
		if err != nil {
			return nil, err
		}
		held, err := cr.BlobsWhere(versionPaths("findings/"+c.Dir+"/attachments/"+name, fid, name))
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(held, func(b string) bool { return old[b] }) {
			out = append(out, c)
		}
	}
	return out, nil
}

// finishCleanup completes an earlier purge of the engagement that stopped
// after its rewrite (the server stopped, gc failed): the backup refs and
// reflogs go, and gc runs while a purged blob the current files do not
// hold is still on disk (whatever file it was purged for).
func (s *Store) finishCleanup(r *gitrepo.Repo, engID string) error {
	purged, err := s.db.PurgedBlobs(engID)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(purged))
	for b := range purged {
		ids = append(ids, b)
	}
	return r.FinishDrop(ids)
}
