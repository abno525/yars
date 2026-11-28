package store

import (
	"github.com/abno525/yars/internal/db"
)

// What Recover does with one journal row.
const (
	rowNothing  = iota // nothing to write: the row goes without a word
	rowReplayed        // the write was made
	rowUnusable        // the row proves nothing: reported, nothing changed
)

// Recover is the start's pass: it replays the database writes a stop cut
// off after their commit (the journal, db.Intent), then holds the database
// against the finding files (Compare) and keeps the result for the System
// page (AtStart). It runs before the first request, and not while another
// server answers on the data folder.
//
// A journal row alone decides nothing. A write is replayed only when the
// finding's file has the digest the row says the commit gave it, and it is
// made as the live code makes it: in one transaction that reads the state as
// it is now. So an approval is carried only while it still counts for the
// text before the commit, and a rename moves only what is still bound to
// it. A row whose file has the digest from before the commit is a commit
// that never landed; it goes. Any other row is said in one warn line and
// goes too: it can never apply later.
//
// Each write made is named in an audit row (system.repair, by yars) and a
// warn line, by engagement and finding ID. No event is sent: a replay keeps
// an approval or moves hashes to text that reads the same, and nobody's
// decision changes.
func (s *Store) Recover() (Integrity, error) {
	if s.db == nil {
		return Integrity{}, ErrNoDB
	}
	rows, err := s.db.Intents()
	if err != nil {
		return Integrity{}, err
	}
	var replayed, unreplayed []string
	for _, in := range rows {
		name := shownEng(in.Eng) + "/" + LogID(in.Fid)
		switch s.replay(in) {
		case rowReplayed:
			replayed = append(replayed, name)
		case rowUnusable:
			unreplayed = append(unreplayed, name)
		}
	}
	res, err := s.Compare()
	res.Replayed, res.Unreplayed = replayed, unreplayed
	if err != nil {
		return res, err
	}
	if res.Faults() > 0 {
		s.Log().Warn("start: the database and the finding files disagree; see Admin, System, Health",
			"duplicate_ids", len(res.Duplicate), "unreadable", len(res.Unreadable))
	}
	s.atStart.Store(&res)
	return res, nil
}

// AtStart is what Recover found at the start; false when it did not run
// (another server answered on the data folder, or it failed).
func (s *Store) AtStart() (Integrity, bool) {
	if res := s.atStart.Load(); res != nil {
		return *res, true
	}
	return Integrity{}, false
}

// replay handles one journal row, under its engagement's lock.
func (s *Store) replay(in db.Intent) int {
	eng, fid := shownEng(in.Eng), LogID(in.Fid)
	drop := func() {
		if err := s.db.DropIntentRow(in); err != nil {
			s.Log().Error("start: a journal row is not removed", "eng", eng, "finding", fid, "err", err)
		}
	}
	unusable := func() int {
		s.Log().Warn("start: a journal row matches nothing and is dropped; nothing was changed", "eng", eng, "finding", fid)
		drop()
		return rowUnusable
	}
	// the row is data (a database can be restored from an uploaded backup):
	// its names are checked before they reach a path
	if !ValidID(in.Eng) || !idOnlyRe.MatchString(in.Fid) || in.Old == "" || in.New == "" || in.Old == in.New ||
		(in.Kind != db.IntentCarry && in.Kind != db.IntentRename) {
		return unusable()
	}
	unlock := s.LockEngagement(in.Eng)
	defer unlock()
	ref, _, err := s.read(in.Eng, in.Fid, nil)
	if err != nil || ref.F.Meta.ID != in.Fid {
		return unusable()
	}
	switch ref.Full {
	case in.Old:
		drop() // the commit never landed
		return rowNothing
	case in.New:
	default:
		return unusable()
	}
	wrote, detail := false, ""
	err = s.db.TxFor(in.Eng, func(tx *db.Tx) error {
		wrote = false
		if err := tx.DropIntent(in.Eng, in.Fid); err != nil {
			return err
		}
		switch in.Kind {
		case db.IntentCarry:
			// as carryApprovalDB
			detail = "approval carried to the committed text"
			st, err := tx.State(in.Eng, in.Fid)
			if err != nil || !Approved(st, in.Old) || st.ApprovedHash == "" {
				return err
			}
			st.ApprovedHash, wrote = in.New, true
			return tx.PutState(in.Eng, in.Fid, st)
		default:
			// as RenameNames: every statement moves only what is still bound
			// to the old digest, or still under the old section name
			detail = "approval, sign-offs and check run moved to the renamed text"
			before, err := tx.Changed()
			if err != nil {
				return err
			}
			if err := tx.MoveHash(in.Eng, in.Fid, in.Old, in.New); err != nil {
				return err
			}
			for o, n := range in.Sections {
				if err := tx.RetargetResults(in.Eng, in.Fid, "section:"+o, "section:"+n); err != nil {
					return err
				}
				if err := tx.RenameChatSection(in.Eng, in.Fid, o, n); err != nil {
					return err
				}
			}
			after, err := tx.Changed()
			wrote = after > before
			return err
		}
	})
	if err != nil {
		// the row stays: the next start tries again
		s.Log().Error("start: a journaled write is not made", "eng", eng, "finding", fid, "kind", in.Kind, "err", err)
		return rowUnusable
	}
	if !wrote {
		return rowNothing // the live write would have changed nothing either
	}
	if err := s.db.Audit(System.Name, "system.repair", in.Eng+"/"+in.Fid, detail); err != nil {
		s.Log().Error("start: a repair is not in the audit log", "eng", eng, "finding", fid, "err", err)
	}
	s.Log().Warn("start: a database write that a stop cut off was made", "eng", eng, "finding", fid, "kind", in.Kind)
	return rowReplayed
}
