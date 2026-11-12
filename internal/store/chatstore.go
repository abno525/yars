package store

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
)

// Chat returns the finding's chat messages and workflow events (empty when
// none, or without a database).
func (s *Store) Chat(engID, dir string) ([]chat.Message, error) {
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return nil, err
	}
	return s.ChatOf(ref)
}

// ChatOf is Chat for a finding the caller already loaded (no second read).
func (s *Store) ChatOf(ref FindingRef) ([]chat.Message, error) {
	if s.db == nil {
		return nil, nil
	}
	return s.db.Messages(ref.EngID, ref.F.Meta.ID)
}

// EngagementChat returns the chat of every finding in an engagement, keyed
// by finding ID (one query; used for tables and the index).
func (s *Store) EngagementChat(engID string) (map[string][]chat.Message, error) {
	if s.db == nil {
		return map[string][]chat.Message{}, nil
	}
	return s.db.AllMessages(engID)
}

// ErrInvalidChat wraps rejected chat input.
var ErrInvalidChat = errors.New("invalid chat message")

// PanelTargets are the non-text parts of a finding a comment may point at.
var PanelTargets = []string{"Details", "Assets", "CVSS"}

// HideThread hides (on) or shows a resolved thread of the finding for u
// only. Open threads can't be hidden; showing is always allowed.
func (s *Store) HideThread(engID, dir, thread string, on bool, u config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return err
	}
	if on {
		msgs, err := s.ChatOf(ref)
		if err != nil {
			return err
		}
		ok := false
		for _, it := range chat.Timeline(msgs) {
			if it.Thread != nil && it.Thread.Root.ID == thread {
				if !it.Thread.Resolved {
					return fmt.Errorf("%w: only a resolved thread can be hidden", ErrInvalidChat)
				}
				ok = true
			}
		}
		if !ok {
			return fmt.Errorf("%w: no thread %s", ErrInvalidChat, thread)
		}
	}
	return s.db.SetChatHidden(u.Username, engID, ref.F.Meta.ID, thread, on)
}

// HiddenThreads returns the threads of the finding that u hid.
func (s *Store) HiddenThreads(engID, dir string, u config.User) (map[string]bool, error) {
	if s.db == nil {
		return map[string]bool{}, nil
	}
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return nil, err
	}
	return s.db.ChatHidden(u.Username, engID, ref.F.Meta.ID)
}

// PostChat validates and stores a message as u (database, no commit). ID,
// time and user are filled in; the returned message is what was stored.
func (s *Store) PostChat(engID, dir string, m chat.Message, u config.User) (chat.Message, error) {
	m.ID, m.TS, m.User, m.Event, m.Kind = chat.NewID(), time.Now().UTC().Truncate(time.Second), u.Username, "", ""
	m.Text = strings.TrimSpace(m.Text)
	if m.Resolves != "" || m.Reopens != "" {
		m.Text, m.Section = "", "" // markers carry no content
	}
	if s.db == nil {
		return m, ErrNoDB
	}
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return m, err
	}
	if m.Section != "" {
		if _, ok := ref.F.Section(m.Section); !ok && !slices.Contains(s.Config().Sections, m.Section) && !slices.Contains(PanelTargets, m.Section) {
			return m, fmt.Errorf("%w: unknown section %q", ErrInvalidChat, m.Section)
		}
	}
	// validate against the chat inside the write transaction, so two
	// concurrent posts (e.g. resolving the same thread) can't both pass
	fid := ref.F.Meta.ID
	replyTo := ""
	seq, err := s.db.TxForSeq(engID, func(tx *db.Tx) error {
		if err := archivedIn(tx, engID); err != nil {
			return err
		}
		existing, err := tx.Messages(engID, fid)
		if err != nil {
			return err
		}
		if err := chat.Validate(existing, m); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidChat, err)
		}
		if m.Reply != "" {
			if i := slices.IndexFunc(existing, func(x chat.Message) bool { return x.ID == m.Reply }); i >= 0 {
				replyTo = existing[i].User
			}
		}
		return tx.AddMessage(engID, fid, m)
	})
	if err != nil {
		return m, err
	}
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeChat, Seq: seq})
	if m.Text != "" {
		ev := findingEvent(EventChat, u.Username, ref)
		ev.MsgID, ev.Text, ev.Section, ev.Reply, ev.ReplyTo = m.ID, m.Text, m.Section, m.Reply, replyTo
		s.Emit(ev)
	}
	return m, nil
}
