package store

import (
	"fmt"
	"strings"
	"time"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/workflow"
)

// CanDismiss reports whether u may dismiss (or restore) a violation of the
// given level on a finding: warnings need edit rights, errors also the
// reviewer role or more, and in the standard workflow another person than
// the finding's author (dismissRefusal).
func (s *Store) CanDismiss(u config.User, m finding.Meta, level string) bool {
	return s.dismissRefusal(u, m, level) == ""
}

// dismissRefusal is why u may not dismiss (or restore) a violation of the
// given level on the finding ("" when u may). An error on one's own finding
// is another person's to dismiss, whatever the author's role, a director's
// too; the simple workflow, where a team can be one person, keeps it the
// author's.
func (s *Store) dismissRefusal(u config.User, m finding.Meta, level string) string {
	switch {
	case !workflow.CanEdit(u, m) && level != "error":
		return "only someone who may edit the finding can dismiss a warning"
	case !workflow.CanEdit(u, m), level == "error" && !workflow.AtLeast(u, "reviewer"):
		return "only a reviewer or a director can dismiss an error"
	case level == "error" && !s.Flow().Simple && u.Username == m.Author:
		return "an error on your own finding is dismissed by another reviewer or a director"
	}
	return ""
}

// DismissWhy marks the finding's violation (rule, target, quote) as not
// counting: the submit/approve gate ignores it and check runs post no
// comment for it; its open comment is resolved. Warnings need edit rights,
// errors also the reviewer role (CanDismiss). The reason is required: it is
// kept with the dismissal and posted as u's reply in the violation's open
// thread before it is resolved. It covers that one result row: the same
// quote in another place still counts. An empty target is the quote's one
// place (placeOf).
func (s *Store) DismissWhy(engID, dir, rule, target, quote, reason string, u config.User) error {
	reason = strings.TrimSpace(reason)
	if reason == "" { // asked here, not only by the page
		return fmt.Errorf("%w: Reason is required", ErrInvalidValue)
	}
	if msg := reasonTooLong(reason); msg != "" {
		return fmt.Errorf("%w: %s", ErrInvalidValue, msg)
	}
	if s.db == nil {
		return ErrNoDB
	}
	if err := s.writable(engID); err != nil {
		return err
	}
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return err
	}
	if target == "" && quote != "" {
		if target, err = s.placeOf(ref, rule, quote); err != nil {
			return err
		}
	}
	qh := ViolationHash(target, quote)
	level, err := s.violationLevel(ref, rule, qh)
	if err != nil {
		return err
	}
	if level == "" {
		return fmt.Errorf("%w: no violation %s with that quote", ErrInvalidValue, rule)
	}
	if why := s.dismissRefusal(u, ref.F.Meta, level); why != "" {
		return &workflow.Denied{Reason: why}
	}
	fid := ref.F.Meta.ID
	k := db.DismissKey(rule, qh)
	resolved := false // the violation's threads were resolved: the chat changed
	seq, err := s.db.TxForSeq(engID, func(tx *db.Tx) error {
		if err := archivedIn(tx, engID); err != nil {
			return err
		}
		if err := tx.Dismiss(db.Dismissal{Eng: engID, Fid: fid, Rule: rule, QuoteHash: qh, Level: level, By: u.Username, Reason: reason}); err != nil {
			return err
		}
		refs, err := tx.CheckThreadRefs(engID, fid)
		if err != nil {
			return err
		}
		mine := map[string]bool{} // the violation's threads (one per section)
		for _, r := range refs {
			if db.DismissKey(r.Rule, r.QuoteHash) == k {
				mine[r.Thread] = true
			}
		}
		if len(mine) == 0 {
			return nil
		}
		msgs, err := tx.Messages(engID, fid)
		if err != nil {
			return err
		}
		for _, it := range chat.Timeline(msgs) {
			if it.Thread != nil && mine[it.Thread.Root.ID] && !it.Thread.Resolved {
				if reason != "" {
					if err := tx.AddMessage(engID, fid, chat.Message{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second),
						User: u.Username, Reply: it.Thread.Root.ID, Text: reason}); err != nil {
						return err
					}
				}
				if err := tx.AddMessage(engID, fid, chat.Message{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second),
					User: u.Username, Resolves: it.Thread.Root.ID}); err != nil {
					return err
				}
				resolved = true
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.db.Audit(u.Username, "check.dismiss", engID+"/"+fid, dismissDetail(rule, level, target)+" · "+reason)
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeState, Seq: seq})
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	if resolved { // the section panels' counts and the chat list follow
		s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeChat, Seq: seq})
	}
	return nil
}

// dismissDetail names a result row in the audit log: its rule, level and
// place. The quote stays out: it is finding text (for a secrets rule the
// secret itself), and the audit log is kept longer and read more widely
// than the finding.
func dismissDetail(rule, level, target string) string {
	if target == "" {
		target = "finding"
	}
	return rule + " · " + level + " · " + target
}

// Undismiss makes a dismissed violation (rule, target, quote) count again;
// the same people who may dismiss it may do this. It asks for no reason;
// like a dismissal it leaves a row in the audit log.
func (s *Store) Undismiss(engID, dir, rule, target, quote string, u config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	if err := s.writable(engID); err != nil {
		return err
	}
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return err
	}
	if target == "" && quote != "" {
		if target, err = s.placeOf(ref, rule, quote); err != nil {
			return err
		}
	}
	fid, qh := ref.F.Meta.ID, ViolationHash(target, quote)
	ds, err := s.db.Dismissals(engID, fid)
	if err != nil {
		return err
	}
	// its own dismissal, or one made before they were per row (that one
	// covered the quote everywhere: restoring this row ends it)
	legacy := ""
	d, ok := ds[db.DismissKey(rule, qh)]
	if quote != "" {
		if old, has := ds[db.DismissKey(rule, db.LegacyHash(quote))]; has {
			legacy = db.LegacyHash(quote)
			if !ok {
				d, ok = old, true
			}
		}
	}
	if !ok {
		return nil
	}
	if why := s.dismissRefusal(u, ref.F.Meta, d.Level); why != "" {
		return &workflow.Denied{Reason: why}
	}
	seq, err := s.db.TxForSeq(engID, func(tx *db.Tx) error {
		if err := archivedIn(tx, engID); err != nil {
			return err
		}
		if legacy != "" {
			if err := tx.Undismiss(engID, fid, rule, legacy); err != nil {
				return err
			}
		}
		return tx.Undismiss(engID, fid, rule, qh)
	})
	if err != nil {
		return err
	}
	// the dismissal's row is gone: the audit log keeps who had made it and why
	was := "dismissed by " + d.By
	if d.Reason != "" {
		was += ": " + d.Reason
	}
	s.db.Audit(u.Username, "check.restore", engID+"/"+fid, dismissDetail(rule, d.Level, target)+" · "+was)
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeState, Seq: seq})
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	return nil
}
