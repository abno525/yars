package store

import (
	"strings"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/workflow"
)

// ErrArchived: the engagement is archived, so it can be read but not changed.
var ErrArchived = db.ErrArchived

// SeesAll reports whether u sees every engagement regardless of teams:
// directors and admins.
func SeesAll(u config.User) bool { return u.IsAdmin || workflow.AtLeast(u, "director") }

// CanSee reports whether u may see engagement eng: directors and admins
// always, others when they are on its team. Without a database (a local
// clone) everything is visible. A team read that fails is false.
func (s *Store) CanSee(u config.User, eng string) bool {
	ok, err := s.Sees(u, eng)
	return err == nil && ok
}

// Sees is CanSee with the team read's error.
func (s *Store) Sees(u config.User, eng string) (bool, error) {
	if s.db == nil || SeesAll(u) {
		return true, nil
	}
	return s.db.IsMember(eng, u.Username)
}

// CanReview reports whether u may be assigned as a reviewer of m in
// engagement eng: an enabled, eligible account (workflow.ReviewerCandidate)
// that can see the engagement.
func (s *Store) CanReview(u config.User, eng string, m finding.Meta) bool {
	ok, err := s.MayReview(u, eng, m)
	return err == nil && ok
}

// MayReview is CanReview with the team read's error.
func (s *Store) MayReview(u config.User, eng string, m finding.Meta) (bool, error) {
	if u.Disabled || !workflow.ReviewerCandidate(u, m) {
		return false, nil
	}
	return s.Sees(u, eng)
}

// Visible returns the engagements u may see; nil means all of them.
func (s *Store) Visible(u config.User) (map[string]bool, error) {
	if s.db == nil || SeesAll(u) {
		return nil, nil
	}
	return s.db.MemberOf(u.Username)
}

// Notifications lists u's newest notifications (unread: only unread ones),
// leaving out those of engagements u can't see.
func (s *Store) Notifications(u config.User, unread bool, limit int) ([]db.Notification, error) {
	if s.db == nil {
		return nil, ErrNoDB
	}
	return s.db.NotificationsFor(u.Username, SeesAll(u), unread, limit)
}

// NotificationPage is a page of u's notifications newest first, as
// Notifications filters them, of the engagements engs when given, older
// than the id before (0: from the newest).
func (s *Store) NotificationPage(u config.User, unread bool, engs []string, before int64, limit int) ([]db.Notification, error) {
	if s.db == nil {
		return nil, ErrNoDB
	}
	return s.db.NotificationPage(u.Username, SeesAll(u), unread, engs, before, limit)
}

// UnreadNotes lists u's newest unread notifications, as Notifications
// filters them, without the events in skip and the engagements in skipEngs,
// at most limit, and how many there are in all.
func (s *Store) UnreadNotes(u config.User, skip, skipEngs []string, limit int) ([]db.Notification, int, error) {
	if s.db == nil {
		return nil, 0, nil
	}
	return s.db.UnreadNotes(u.Username, SeesAll(u), skip, skipEngs, limit)
}

// MarkNotesRead marks read what UnreadNotes lists for the same filters.
func (s *Store) MarkNotesRead(u config.User, skip, skipEngs []string) error {
	if s.db == nil {
		return ErrNoDB
	}
	return s.db.MarkNotesRead(u.Username, SeesAll(u), skip, skipEngs)
}

// UnreadCount is how many of u's notifications of engagements u can see
// are unread (the notifications page).
func (s *Store) UnreadCount(u config.User) (int, error) {
	if s.db == nil {
		return 0, nil
	}
	return s.db.UnreadCountFor(u.Username, SeesAll(u))
}

// canManageTeam: directors and admins change teams and archive.
func canManageTeam(u config.User) bool { return SeesAll(u) }

// AddMembers puts users on eng's team as actor (directors and admins).
func (s *Store) AddMembers(eng string, users []string, actor config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	if !canManageTeam(actor) {
		return &workflow.Denied{Reason: "only a director or an admin can change the team"}
	}
	if _, err := s.Engagement(eng); err != nil {
		return err
	}
	if err := s.db.AddMembers(eng, users...); err != nil {
		return err
	}
	return s.db.Audit(actor.Username, "eng.member.add", eng, strings.Join(users, ","))
}

// RemoveMember takes user off eng's team as actor (directors and admins).
func (s *Store) RemoveMember(eng, user string, actor config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	if !canManageTeam(actor) {
		return &workflow.Denied{Reason: "only a director or an admin can change the team"}
	}
	if err := s.db.RemoveMember(eng, user); err != nil {
		return err
	}
	return s.db.Audit(actor.Username, "eng.member.remove", eng, user)
}

// Members lists eng's team.
func (s *Store) Members(eng string) ([]string, error) {
	if s.db == nil {
		return nil, ErrNoDB
	}
	return s.db.Members(eng)
}

// Archived reports whether eng is archived (read only).
func (s *Store) Archived(eng string) bool {
	if s.db == nil {
		return false
	}
	m, err := s.db.EngMeta(eng)
	return err == nil && m.Archived
}

// EngMeta returns eng's archive state.
func (s *Store) EngMeta(eng string) (db.EngMeta, error) {
	if s.db == nil {
		return db.EngMeta{}, nil
	}
	return s.db.EngMeta(eng)
}

// cmpErr returns err when set, else fallback.
func cmpErr(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

// archivedIn refuses, inside a write transaction, a change to an archived
// engagement, so the write can't slip in next to an archive.
func archivedIn(tx *db.Tx, eng string) error {
	if a, err := tx.Archived(eng); err != nil || a {
		return cmpErr(err, ErrArchived)
	}
	return nil
}

// writable refuses changes to an archived engagement. Git writes call it
// under the engagement lock (Archive takes it too); database writes check
// inside their transaction (archivedIn).
func (s *Store) writable(eng string) error {
	if s.db == nil {
		return nil
	}
	m, err := s.db.EngMeta(eng)
	if err != nil {
		return err
	}
	if m.Archived {
		return ErrArchived
	}
	return nil
}

// Archive makes eng read only (directors and admins).
func (s *Store) Archive(eng string, u config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	if !canManageTeam(u) {
		return &workflow.Denied{Reason: "only a director or an admin can archive an engagement"}
	}
	if _, err := s.Engagement(eng); err != nil {
		return err
	}
	// a git write in progress finishes first; later ones see the archive
	// (they check it under this lock)
	l := s.engLock(eng)
	l.Lock()
	err := s.db.Archive(eng, u.Username)
	l.Unlock()
	if err != nil {
		return err
	}
	return s.db.Audit(u.Username, "eng.archive", eng, "")
}

// Unarchive reopens eng for changes (directors only).
func (s *Store) Unarchive(eng string, u config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	if !workflow.AtLeast(u, "director") {
		return &workflow.Denied{Reason: "only a director can reopen an archived engagement"}
	}
	if _, err := s.Engagement(eng); err != nil {
		return err
	}
	if err := s.db.Unarchive(eng); err != nil {
		return err
	}
	return s.db.Audit(u.Username, "eng.unarchive", eng, "")
}
