package store

import (
	"fmt"
	"strings"
	"time"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/workflow"
)

// CanDismiss reports whether u may dismiss (or restore) a violation of the
// given level on a finding: warnings need edit rights, errors also the
// reviewer role or more.
func CanDismiss(u config.User, m finding.Meta, level string) bool {
	if !workflow.CanEdit(u, m) {
		return false
	}
	return level != "error" || workflow.AtLeast(u, "reviewer")
}

// Dismiss marks the finding's violation (rule, quote) as not counting: the
// submit/approve gate ignores it and check runs post no comment for it; its
// open comment is resolved. Warnings need edit rights, errors also the
// reviewer role (CanDismiss). The quote must be in one place only (placeOf);
// DismissWhy takes the place.
func (s *Store) Dismiss(engID, dir, rule, quote string, u config.User) error {
	return s.DismissWhy(engID, dir, rule, "", quote, "", u)
}

// DismissWhy is Dismiss of the violation (rule, target, quote) with the
// reason: it is kept with the dismissal and posted as u's reply in the
// violation's open thread before it is resolved. It covers that one result
// row: the same quote in another place still counts. An empty target is
// the quote's one place (placeOf).
func (s *Store) DismissWhy(engID, dir, rule, target, quote, reason string, u config.User) error {
	reason = strings.TrimSpace(reason)
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
	if !CanDismiss(u, ref.F.Meta, level) {
		return &workflow.Denied{Reason: dismissDenied(level)}
	}
	fid := ref.F.Meta.ID
	k := db.DismissKey(rule, qh)
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
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeState, Seq: seq})
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	return nil
}

func dismissDenied(level string) string {
	if level == "error" {
		return "only a reviewer or a director can dismiss an error"
	}
	return "only someone who may edit the finding can dismiss a warning"
}

// Undismiss makes a dismissed violation (rule, target, quote) count again;
// the same people who may dismiss it may do this.
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
	if !CanDismiss(u, ref.F.Meta, d.Level) {
		return &workflow.Denied{Reason: dismissDenied(d.Level)}
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
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeState, Seq: seq})
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeCheck})
	return nil
}
