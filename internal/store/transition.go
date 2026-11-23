package store

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/rules"
	"yars/internal/workflow"
)

// SetRetestResult records the outcome of a retested finding (database).
func (s *Store) SetRetestResult(engID, dir, result string, a Actor) error {
	return s.setRetestResult(engID, dir, nil, result, a)
}

// SetRetestResultFrom is SetRetestResult for a choice made on a page that
// showed the result was ("" = none): another result stored since is
// ErrConflict.
func (s *Store) SetRetestResultFrom(engID, dir, was, result string, a Actor) error {
	return s.setRetestResult(engID, dir, &was, result, a)
}

func (s *Store) setRetestResult(engID, dir string, was *string, result string, a Actor) error {
	if !slices.Contains(workflow.RetestResults, result) {
		return fmt.Errorf("%w: retest result must be fixed, not_fixed or partially_fixed", ErrInvalidValue)
	}
	return s.changeState(engID, dir, func(ref FindingRef, st *db.State, _ string) ([]chat.Message, error) {
		if u, ok := a.(config.User); ok && !workflow.CanEdit(u, ref.F.Meta) {
			return nil, &workflow.Denied{Reason: "this finding is " + ref.F.Meta.Status + "; only a director can edit it"}
		}
		if st.RetestSource == "" {
			return nil, fmt.Errorf("%w: %s is not a retest finding", ErrInvalidValue, ref.F.Meta.ID)
		}
		if st.RetestResult == result { // already so (a second click too)
			return nil, nil
		}
		if was != nil && *was != st.RetestResult {
			return nil, ErrConflict
		}
		var u string
		if cu, ok := a.(config.User); ok {
			u = cu.Username
		} else {
			u = a.GitAuthor().Name
		}
		st.RetestResult = result
		if st.Status == "verification" {
			// reviewers cleared a different outcome
			for i := range st.Reviewers {
				st.Reviewers[i].ClearedHash = ""
			}
		}
		return []chat.Message{{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second), User: u, Event: "retest", Text: workflow.RetestLabel(result)}}, nil
	})
}

// changeState loads a finding, lets fn change its state, and stores it —
// with any workflow events fn returns — in one database transaction. No git
// commit is made and no git lock is taken: the state is bound to the content
// hash read here, so a concurrent edit makes it stale rather than wrong
// (clearances and approvals count only for the content they were given for).
func (s *Store) changeState(engID, dir string, fn func(ref FindingRef, st *db.State, hash string) ([]chat.Message, error)) error {
	if s.db == nil {
		return ErrNoDB
	}
	ref, raw, err := s.read(engID, dir, nil)
	if err != nil {
		return err
	}
	fid, hash := ref.F.Meta.ID, contentHash(raw)
	// read-modify-write inside one write transaction, so another writer
	// (a request, yars export --mark) can't interleave
	seq, err := s.db.TxForSeq(engID, func(tx *db.Tx) error {
		if err := archivedIn(tx, engID); err != nil {
			return err
		}
		st, err := tx.State(engID, fid)
		if err != nil {
			return err
		}
		applyState(&ref.F.Meta, st, hash, s.Flow())
		msgs, err := fn(ref, &st, hash)
		if err != nil {
			return err
		}
		if err := tx.PutState(engID, fid, st); err != nil {
			return err
		}
		for _, m := range msgs {
			if err := tx.AddMessage(engID, fid, m); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeState, Seq: seq})
	return nil
}

// Transition applies a workflow action as u: the state changes in the
// database together with a workflow event in the chat (no git commit).
// Permission and gate failures are *workflow.Denied.
func (s *Store) Transition(engID, dir string, act workflow.Action, reason string, u config.User) error {
	return s.TransitionChecked(engID, dir, act, reason, u, nil)
}

// TransitionChecked is Transition with a further rule of the caller (the
// bulk bar's own limits), checked on the finding as it is inside the change.
func (s *Store) TransitionChecked(engID, dir string, act workflow.Action, reason string, u config.User, check func(finding.Meta) error) error {
	return s.transition(engID, dir, act, reason, "", "", u, check)
}

// TransitionSeen is Transition for a page that showed the content with hash
// seen and the attachments with AttachmentsHash files: a sign-off or an
// approval of a finding changed since is refused (ErrConflict). seen or
// files "" is not checked; another action: Transition.
func (s *Store) TransitionSeen(engID, dir string, act workflow.Action, reason, seen, files string, u config.User) error {
	if !SignsOff(act) {
		seen, files = "", ""
	}
	return s.transition(engID, dir, act, reason, seen, files, u, nil)
}

// changedSince refuses a sign-off or an approval of a version the page did
// not show.
func changedSince() error {
	return &workflow.Denied{Reason: "the finding changed since you opened it; read it again", Err: ErrConflict}
}

func (s *Store) transition(engID, dir string, act workflow.Action, reason, seen, files string, u config.User, check func(finding.Meta) error) error {
	if check == nil {
		check = func(finding.Meta) error { return nil }
	}
	if !workflow.NeedsReason(act) {
		reason = "" // only Return, Withdraw and the reverts carry one
	}
	if s.db == nil {
		return ErrNoDB
	}
	if err := s.writable(engID); err != nil {
		return err
	}
	// Style rules (scripts, AI) can be slow, so they run outside the lock on
	// a snapshot; the change is refused if the finding changed meanwhile.
	linted := ""
	if (workflow.Gated(act) || SignsOff(act)) && s.Linter != nil {
		ref, raw, err := s.read(engID, dir, nil)
		if err != nil {
			return err
		}
		if seen != "" && contentHash(raw) != seen {
			// first, as in the change: no gate or rule for content not seen
			return changedSince()
		}
		if err := workflow.CheckWithGate(u, ref.F.Meta, act, s.Config()); err != nil {
			return err
		}
		if err := check(ref.F.Meta); err != nil {
			return err
		}
		errs, err := s.blocking(act, ref, contentHash(raw), u, rules.All)
		if err != nil {
			return err
		}
		if len(errs) > 0 {
			return &workflow.Denied{Reason: "cannot " + strings.ToLower(workflow.Label(act)) + ": " + strings.Join(errs, "; ")}
		}
		linted = contentHash(raw)
	}
	var done Event
	err := s.changeState(engID, dir, func(ref FindingRef, st *db.State, hash string) ([]chat.Message, error) {
		done = findingEvent(EventStatus, u.Username, ref)
		done.Action, done.From, done.Reason = string(act), ref.F.Meta.Status, strings.TrimSpace(reason)
		changed := seen != "" && hash != seen
		if files != "" && !changed {
			// read inside the transaction: a file written before it is seen
			// here; one written after clears a sign-off given here
			// (dropSignOffs, in verification)
			now, err := s.AttachmentsHash(engID, ref.Dir)
			if err != nil {
				return nil, err
			}
			changed = now != files
		}
		if changed {
			return nil, changedSince()
		}
		if linted != "" && hash != linted {
			return nil, &workflow.Denied{Reason: "the finding changed while its checks ran; try again", Err: ErrConflict}
		}
		if linted != "" && SignsOff(act) {
			// a run started since the read above: the content it covers now
			if g, err := s.checkGate(engID, ref.F.Meta.ID, hash); err != nil {
				return nil, err
			} else if g != "" {
				return nil, &workflow.Denied{Reason: "cannot " + strings.ToLower(workflow.Label(act)) + ": " + g}
			}
		}
		if err := workflow.CheckWithGate(u, ref.F.Meta, act, s.Config()); err != nil {
			return nil, err
		}
		if err := check(ref.F.Meta); err != nil {
			return nil, err
		}
		uncleared := func() {
			for i := range st.Reviewers {
				st.Reviewers[i].ClearedHash = ""
			}
		}
		ev := chat.Message{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second), User: u.Username, Event: string(act)}
		switch act {
		case workflow.Submit:
			uncleared()
			st.ReturnedBy, st.ReturnedReason = "", ""
		case workflow.Return:
			r := strings.TrimSpace(reason)
			if r == "" {
				return nil, &workflow.Denied{Reason: "a reason is required to return a finding"}
			}
			uncleared()
			st.ReturnedBy, st.ReturnedReason, ev.Text = u.Username, r, r
		case workflow.Withdraw:
			r := strings.TrimSpace(reason)
			if r == "" {
				return nil, &workflow.Denied{Reason: "a reason is required to withdraw a finding"}
			}
			uncleared()
			st.ApprovedHash = ""
			st.ReturnedBy, st.ReturnedReason = "", ""
			st.WithdrawnBy, st.WithdrawnReason, ev.Text = u.Username, r, r
		case workflow.Revise:
			uncleared()
			st.WithdrawnBy, st.WithdrawnReason = "", ""
			st.ReturnedBy, st.ReturnedReason = "", ""
		case workflow.Clear:
			// the clearance is for exactly this content; a director reviewing
			// unassigned joins the reviewers
			i := slices.IndexFunc(st.Reviewers, func(r db.Reviewer) bool { return r.Name == u.Username })
			if i < 0 {
				st.Reviewers = append(st.Reviewers, db.Reviewer{Name: u.Username})
				i = len(st.Reviewers) - 1
			}
			st.Reviewers[i].ClearedHash = hash
		case workflow.Reopen:
			r := strings.TrimSpace(reason)
			if r == "" {
				return nil, &workflow.Denied{Reason: "a reason is required to revert a finding"}
			}
			uncleared()
			st.ApprovedHash = ""
			ev.Text = r
		case workflow.Unreport:
			// back to complete: the approval, the sign-offs and the remote
			// pages of earlier exports stay (R4)
			r := strings.TrimSpace(reason)
			if r == "" {
				return nil, &workflow.Denied{Reason: "a reason is required to revert a finding"}
			}
			ev.Text = r
		case workflow.TakeBack:
			uncleared() // the author changes it again: sign-offs start over
			st.ReturnedBy, st.ReturnedReason = "", ""
		case workflow.Approve:
			st.ApprovedHash = hash // approval is for exactly this content
		case workflow.Complete:
			// the simple workflow's approval: for exactly this content, so
			// an edit through YARS keeps it complete (carryApproval)
			uncleared()
			st.ReturnedBy, st.ReturnedReason = "", ""
			st.ApprovedHash = hash
		}
		_, st.Status = s.Flow().Target(act)
		return []chat.Message{ev}, nil
	})
	if err != nil {
		return err
	}
	_, done.To = s.Flow().Target(act)
	s.Emit(done)
	return nil
}

// MarkExported marks a complete finding reported because u sent it to a
// destination that marks what it gets (mark_reported). It is the
// destination's doing, not u's workflow power, so any sender may; the
// event's text names the destination. Not complete: *workflow.Denied.
func (s *Store) MarkExported(engID, dir, destination string, u config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	if err := s.writable(engID); err != nil {
		return err
	}
	var done Event
	err := s.changeState(engID, dir, func(ref FindingRef, st *db.State, _ string) ([]chat.Message, error) {
		from, to := s.Flow().Target(workflow.Report)
		if !slices.Contains(from, ref.F.Meta.Status) {
			return nil, &workflow.Denied{Reason: ref.F.Meta.ID + " is " + ref.F.Meta.Status + ", not complete"}
		}
		done = findingEvent(EventStatus, u.Username, ref)
		done.Action, done.From, done.To, done.Destination = string(workflow.Report), ref.F.Meta.Status, to, destination
		st.Status = to
		return []chat.Message{{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second), User: u.Username,
			Event: string(workflow.Report), Text: destination}}, nil
	})
	if err == nil {
		s.Emit(done)
	}
	return err
}

// SetReviewers replaces the reviewer list as u. The author is never
// assigned: a director author's own sign-off (Q25) is kept as it is, and
// dropped with the next list once a return or a take back cleared it.
// Clearances of reviewers who stay are kept. The simple workflow has no
// reviewers: refused (*workflow.Denied).
func (s *Store) SetReviewers(engID, dir string, names []string, u config.User) error {
	if err := s.noReviewers(); err != nil {
		return err
	}
	var done Event
	err := s.changeState(engID, dir, func(ref FindingRef, st *db.State, _ string) ([]chat.Message, error) {
		m := ref.F.Meta
		if !workflow.CanAddReviewers(u, m) {
			return nil, reviewersDenied(m)
		}
		done = findingEvent(EventReviewers, u.Username, ref)
		done.State = m.Status
		var list []string
		for _, n := range names {
			if n = strings.TrimSpace(n); n != "" && n != m.Author && !slices.Contains(list, n) {
				list = append(list, n)
			}
		}
		if !workflow.CanAssign(u, m) {
			// a reviewer only adds: nobody assigned (or signed off) is dropped
			for _, old := range st.Reviewers {
				if old.Name != m.Author && !slices.Contains(list, old.Name) {
					return nil, &workflow.Denied{Reason: "only the author or a director can remove a reviewer"}
				}
			}
			isOld := func(n string) bool {
				return slices.ContainsFunc(st.Reviewers, func(r db.Reviewer) bool { return r.Name == n })
			}
			for _, n := range list {
				if !isOld(n) && !workflow.CanAddReviewer(u, m, n) {
					return nil, &workflow.Denied{Reason: errSelfAssign}
				}
			}
		}
		if len(list) == 0 && m.Status == "verification" {
			// nobody could sign it off: it would wait for ever
			return nil, &workflow.Denied{Reason: "a finding in verification keeps at least one reviewer"}
		}
		if slices.ContainsFunc(st.Reviewers, func(r db.Reviewer) bool { return r.Name == m.Author && r.ClearedHash != "" }) {
			list = append(list, m.Author) // the author's own sign-off stays
		}
		sort.Strings(list)
		var next []db.Reviewer
		done.Reviewers, done.Added = list, nil
		for _, n := range list {
			r := db.Reviewer{Name: n}
			added := true
			for _, old := range st.Reviewers {
				if old.Name == n {
					r.ClearedHash, added = old.ClearedHash, false
				}
			}
			if added {
				done.Added = append(done.Added, n)
			}
			next = append(next, r)
		}
		st.Reviewers = next
		return nil, nil
	})
	if err == nil && len(done.Added) > 0 {
		s.Emit(done)
	}
	return err
}

const errSelfAssign = "only the author or a director can make you a reviewer"

// noReviewers refuses a change of the reviewer list in a workflow without
// reviewers (the simple one).
func (s *Store) noReviewers() error {
	if !s.Flow().HasReviewers() {
		return &workflow.Denied{Reason: "the simple workflow has no reviewers"}
	}
	return nil
}

// reviewersDenied is why the reviewer list of m cannot change: the finding
// is no longer open, or the user may not assign.
func reviewersDenied(m finding.Meta) error {
	if m.Status != "draft" && m.Status != "verification" {
		return &workflow.Denied{Reason: "reviewers can only change in draft or verification (finding is " + m.Status + ")"}
	}
	return &workflow.Denied{Reason: "only a reviewer, the author or a director can assign reviewers"}
}

// AddReviewers adds names to the reviewer list as u, merged with the list as
// it is inside the change, so a reviewer someone added meanwhile (and their
// sign-off) stays. The author's name, and u's own when u may only add
// (workflow.CanAddReviewer), are skipped; when no name could be added and
// none was on the list already, it is *workflow.Denied (as it is in the
// simple workflow, which has no reviewers).
func (s *Store) AddReviewers(engID, dir string, names []string, u config.User) error {
	if err := s.noReviewers(); err != nil {
		return err
	}
	var done Event
	err := s.changeState(engID, dir, func(ref FindingRef, st *db.State, _ string) ([]chat.Message, error) {
		m := ref.F.Meta
		if !workflow.CanAddReviewers(u, m) {
			return nil, reviewersDenied(m)
		}
		done = findingEvent(EventReviewers, u.Username, ref)
		done.State = m.Status
		var refused []string
		kept := false
		for _, n := range names {
			switch n = strings.TrimSpace(n); {
			case n == "":
			case slices.ContainsFunc(st.Reviewers, func(r db.Reviewer) bool { return r.Name == n }):
				kept = true
			case n == m.Author:
				refused = append(refused, n+" wrote this finding")
			case !workflow.CanAddReviewer(u, m, n):
				refused = append(refused, errSelfAssign)
			default:
				st.Reviewers = append(st.Reviewers, db.Reviewer{Name: n})
				done.Added = append(done.Added, n)
			}
		}
		if len(done.Added) == 0 && !kept {
			if len(refused) == 0 {
				refused = []string{"no reviewer given"}
			}
			return nil, &workflow.Denied{Reason: strings.Join(refused, "; ")}
		}
		sort.Slice(st.Reviewers, func(i, j int) bool { return st.Reviewers[i].Name < st.Reviewers[j].Name })
		done.Reviewers = nil
		for _, r := range st.Reviewers {
			done.Reviewers = append(done.Reviewers, r.Name)
		}
		return nil, nil
	})
	if err == nil && len(done.Added) > 0 {
		s.Emit(done)
	}
	return err
}
