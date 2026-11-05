package store

import (
	"errors"
	"strings"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/workflow"
)

// ErrArchived: the engagement is archived, so it can be read but not changed.
var ErrArchived = errors.New("the engagement is archived (read only)")

// SeesAll reports whether u sees every engagement regardless of teams:
// directors and admins.
func SeesAll(u config.User) bool { return u.IsAdmin || workflow.AtLeast(u, "director") }

// CanSee reports whether u may see engagement eng: directors and admins
// always, others when they are on its team. Without a database (a local
// clone) everything is visible.
func (s *Store) CanSee(u config.User, eng string) bool {
	if s.db == nil || SeesAll(u) {
		return true
	}
	ok, err := s.db.IsMember(eng, u.Username)
	return err == nil && ok
}

// CanReview reports whether u may be assigned as a reviewer of m in
// engagement eng: an enabled, eligible account (workflow.ReviewerCandidate)
// that can see the engagement.
func (s *Store) CanReview(u config.User, eng string, m finding.Meta) bool {
	return !u.Disabled && workflow.ReviewerCandidate(u, m) && s.CanSee(u, eng)
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

// UnreadCount is how many of u's notifications of engagements u can see
// are unread (the bell).
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

// writable refuses changes to an archived engagement.
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
	if err := s.db.Archive(eng, u.Username); err != nil {
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
