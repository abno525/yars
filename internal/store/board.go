package store

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
)

// The team board: an engagement's notes ("leads") and their analysis
// threads, kept in the database only (never in git, exports or clones).
// Any user who can see the engagement may write on its board; the actor is
// recorded on every entry. Only Make finding copies a note's text into the
// client-facing finding.

type (
	Note       = db.Note
	NoteMsg    = db.NoteMsg
	NoteFilter = db.NoteFilter
	Unseen     = db.Unseen
)

var (
	// ErrBoardStale: the note is no longer in the state the user saw.
	ErrBoardStale = db.ErrBoardStale
	// ErrBoardLocked: the note became a finding (read only).
	ErrBoardLocked = db.ErrBoardLocked
)

// NoteStates are a note's states in board order; Set state offers every one
// but dismissed (Dismiss asks why).
var NoteStates = []string{"open", "analyzing", "confirmed", "info", "dismissed"}

// Limits of what a note holds.
const (
	MaxNoteTitle  = 200
	MaxNoteHost   = 2000
	MaxNoteReason = 1000
)

// FieldError is an invalid value of one form field.
type FieldError struct{ Field, Msg string }

func (e *FieldError) Error() string { return ErrInvalidValue.Error() + ": " + e.Msg }
func (e *FieldError) Unwrap() error { return ErrInvalidValue }

func fieldErr(field, msg string) error { return &FieldError{Field: field, Msg: msg} }

// NoteID is how a note is named: L-001.
func NoteID(num int) string { return fmt.Sprintf("L-%03d", num) }

var refRe = regexp.MustCompile(`^([LlFf])-(\d{1,6})$`)

// ParseNoteID reads "L-014" (or "14").
func ParseNoteID(s string) (int, bool) {
	if m := refRe.FindStringSubmatch(s); m != nil && (m[1] == "L" || m[1] == "l") {
		s = m[2]
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 999999 || strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	return n, true
}

// board checks that the board of eng can be used: a database and an
// engagement.
func (s *Store) board(eng string) error {
	if s.db == nil {
		return ErrNoDB
	}
	_, err := s.Engagement(eng)
	return err
}

// boardErr maps the database's errors to the store's.
func boardErr(err error) error {
	if errors.Is(err, db.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

func oneLine(field, label, v string, max int, required bool) (string, error) {
	v = strings.TrimSpace(v)
	switch {
	case v == "" && required:
		return "", fieldErr(field, "Required")
	case strings.ContainsAny(v, "\r\n"):
		return "", fieldErr(field, label+": one line")
	case len([]rune(v)) > max:
		return "", fieldErr(field, fmt.Sprintf("%s: at most %d characters", label, max))
	}
	return v, nil
}

func noteText(text string) (string, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", fieldErr("text", "Required")
	}
	if len([]rune(text)) > chat.MaxText {
		return "", fieldErr("text", fmt.Sprintf("At most %d characters", chat.MaxText))
	}
	return text, nil
}

// CreateNote adds a note to eng's board: a title (one line), an optional
// host, the first message and a starting state (open or info).
func (s *Store) CreateNote(eng, title, host, state, text string, u config.User) (Note, error) {
	if err := s.board(eng); err != nil {
		return Note{}, err
	}
	title, err := oneLine("title", "Title", title, MaxNoteTitle, true)
	if err != nil {
		return Note{}, err
	}
	if host, err = oneLine("host", "Host", host, MaxNoteHost, false); err != nil {
		return Note{}, err
	}
	if state == "" {
		state = "open"
	}
	if state != "open" && state != "info" {
		return Note{}, fieldErr("state", "Open or Info")
	}
	if text, err = noteText(text); err != nil {
		return Note{}, err
	}
	// the first message is what Make finding makes the description of
	if finding.ValidateBody(text) != nil {
		return Note{}, fieldErr("text", "No ## heading or open ``` fence: it becomes the description")
	}
	n, err := s.db.CreateNote(db.Note{Eng: eng, Title: title, Host: host, Author: u.Username, State: state}, text)
	return n, boardErr(err)
}

// Note returns one note of eng.
func (s *Store) Note(eng string, num int) (Note, error) {
	if err := s.board(eng); err != nil {
		return Note{}, err
	}
	n, err := s.db.Note(eng, num)
	return n, boardErr(err)
}

// Notes returns eng's notes that f picks, the latest activity first.
func (s *Store) Notes(eng string, f NoteFilter) ([]Note, error) {
	if err := s.board(eng); err != nil {
		return nil, err
	}
	if f.State != "" && !slices.Contains(NoteStates, f.State) {
		f.State = ""
	}
	return s.db.Notes(eng, f)
}

// NoteCounts counts eng's notes by state.
func (s *Store) NoteCounts(eng string) (map[string]int, error) {
	if err := s.board(eng); err != nil {
		return nil, err
	}
	return s.db.NoteCounts(eng)
}

// NoteMessages returns a note's timeline: the first message and the newest
// limit-1 entries (older: how many are left out).
func (s *Store) NoteMessages(eng string, num, limit int) ([]NoteMsg, int, error) {
	if err := s.board(eng); err != nil {
		return nil, 0, err
	}
	return s.db.NoteMessages(eng, num, limit)
}

// NoteStamp changes with every board write of eng.
func (s *Store) NoteStamp(eng string) (int64, error) {
	if s.db == nil {
		return 0, ErrNoDB
	}
	return s.db.NoteStamp(eng)
}

// PostNote adds u's message to a note.
func (s *Store) PostNote(eng string, num int, text string, u config.User) error {
	if err := s.board(eng); err != nil {
		return err
	}
	text, err := noteText(text)
	if err != nil {
		return err
	}
	_, err = s.db.PostNote(eng, num, u.Username, text)
	return boardErr(err)
}

func validState(st string) bool { return slices.Contains(NoteStates, st) }

// SetNoteState moves a note from the state the user saw (from) to another
// one; dismissing goes through DismissNote.
func (s *Store) SetNoteState(eng string, num int, from, to string, u config.User) error {
	if err := s.board(eng); err != nil {
		return err
	}
	switch {
	case !validState(from) || !validState(to):
		return fieldErr("state", "Unknown state")
	case to == "dismissed":
		return fieldErr("state", "Dismiss asks for a reason")
	case to == from:
		return fieldErr("state", "Already "+to)
	}
	return boardErr(s.db.SetNoteState(eng, num, u.Username, from, to, ""))
}

// DismissNote dismisses a note, with a reason.
func (s *Store) DismissNote(eng string, num int, from, reason string, u config.User) error {
	if err := s.board(eng); err != nil {
		return err
	}
	if !validState(from) {
		return fieldErr("state", "Unknown state")
	}
	if from == "dismissed" {
		return fieldErr("state", "Already dismissed")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return fieldErr("reason", "Required")
	}
	if len([]rune(reason)) > MaxNoteReason {
		return fieldErr("reason", fmt.Sprintf("At most %d characters", MaxNoteReason))
	}
	return boardErr(s.db.SetNoteState(eng, num, u.Username, from, "dismissed", reason))
}

// SetNoteSeverity sets a note's likely severity: one of the configured
// severities, or "" (unset).
func (s *Store) SetNoteSeverity(eng string, num int, sev string, u config.User) error {
	if err := s.board(eng); err != nil {
		return err
	}
	if sev != "" && !slices.Contains(s.Config().Severities, sev) {
		return fieldErr("severity", "Unknown severity")
	}
	return boardErr(s.db.SetNoteSeverity(eng, num, u.Username, sev))
}

// SetNoteDup records what a note duplicates: another note (L-…) or a
// finding (F-…) of the same engagement, never itself and never a note that
// duplicates this one; "" clears it. It returns the stored form ("L-002").
func (s *Store) SetNoteDup(eng string, num int, ref string, u config.User) (string, error) {
	if err := s.board(eng); err != nil {
		return "", err
	}
	ref = strings.TrimSpace(ref)
	if ref != "" {
		m := refRe.FindStringSubmatch(ref)
		if m == nil {
			return "", fieldErr("dup", "L-… or F-…")
		}
		k, _ := strconv.Atoi(m[2])
		if strings.EqualFold(m[1], "L") {
			ref = NoteID(k)
			if k == num {
				return "", fieldErr("dup", "Not itself")
			}
			target, err := s.db.Note(eng, k)
			if err != nil {
				return "", boardErrNotFound(err, "No "+ref)
			}
			if target.DupOf == NoteID(num) {
				return "", fieldErr("dup", ref+" is a duplicate of this one")
			}
		} else {
			ref = fmt.Sprintf("F-%03d", k)
			if _, err := s.Finding(eng, strconv.Itoa(k)); err != nil {
				return "", boardErrNotFound(err, "No "+ref)
			}
		}
	}
	return ref, boardErr(s.db.SetNoteDup(eng, num, u.Username, ref))
}

// boardErrNotFound turns a missing target into a field error.
func boardErrNotFound(err error, msg string) error {
	if errors.Is(err, db.ErrNotFound) || errors.Is(err, ErrNotFound) {
		return fieldErr("dup", msg)
	}
	return err
}

// MakeFinding makes a draft finding of a confirmed or info note, as u (its
// author): the note's title, its host as the asset, its first message as
// the description (the Description section, else the first configured
// one) and its likely severity, in one commit. The note then links to the
// finding and is read only. A claim makes sure only one finding is made.
func (s *Store) MakeFinding(eng string, num int, u config.User) (FindingRef, error) {
	if err := s.board(eng); err != nil {
		return FindingRef{}, err
	}
	n, err := s.db.Note(eng, num)
	if err != nil {
		return FindingRef{}, boardErr(err)
	}
	if n.Finding == "" && !n.Pending && n.State != "confirmed" && n.State != "info" {
		return FindingRef{}, fieldErr("state", "Only a confirmed or info note becomes a finding")
	}
	if s.beforeClaim != nil {
		s.beforeClaim()
	}
	if err := s.db.ClaimNote(eng, num); err != nil {
		return FindingRef{}, boardErr(err)
	}
	// the note as claimed: nothing changes it any more
	if n, err = s.db.Note(eng, num); err != nil {
		s.db.UnclaimNote(eng, num)
		return FindingRef{}, boardErr(err)
	}
	ref, err := s.findingOfNote(n, u)
	if err != nil {
		s.db.UnclaimNote(eng, num)
		return FindingRef{}, err
	}
	// the finding exists now: the claim must not be given back (a restart
	// would offer Make finding again), so the link is tried twice
	if err = s.db.LinkNote(eng, num, u.Username, ref.F.Meta.ID); err != nil {
		log.Printf("board %s/%s: link to %s: %v (retrying)", eng, NoteID(num), ref.F.Meta.ID, err)
		err = s.db.LinkNote(eng, num, u.Username, ref.F.Meta.ID)
	}
	return ref, err
}

func (s *Store) findingOfNote(n Note, u config.User) (FindingRef, error) {
	msgs, _, err := s.db.NoteMessages(n.Eng, n.Num, 2)
	if err != nil {
		return FindingRef{}, err
	}
	text := ""
	if len(msgs) > 0 {
		text = msgs[0].Text
	}
	if err := finding.ValidateBody(text); err != nil {
		return FindingRef{}, fmt.Errorf("%w: the first message can't be a description: %v", ErrInvalidBody, err)
	}
	sections := s.Config().Sections
	sec := "Description"
	if !slices.Contains(sections, sec) && len(sections) > 0 {
		sec = sections[0]
	}
	var assets []finding.Asset
	if n.Host != "" {
		a := finding.Asset{Host: n.Host}
		if p, err := url.Parse(n.Host); err == nil && p.Scheme != "" && p.Host != "" {
			a = finding.Asset{URL: n.Host}
		}
		if assets, err = CleanAssets([]finding.Asset{a}); err != nil {
			return FindingRef{}, err
		}
	}
	a := AuthorOf(u)
	return s.createFinding(n.Eng, n.Title, a, func(id string) (*finding.Finding, error) {
		f := finding.New(id, n.Title, a.Name, sections)
		if len(sections) > 0 {
			f.SetSection(sec, text+"\n")
		}
		if len(assets) > 0 {
			if err := f.SetMeta("assets", assets); err != nil {
				return nil, err
			}
		}
		if n.Severity != "" {
			if err := f.SetMeta("severity", n.Severity); err != nil {
				return nil, err
			}
		}
		return f, nil
	})
}

// SeeNote records that u saw a note as it is now.
func (s *Store) SeeNote(eng string, num int, u config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	return s.db.SeeNote(u.Username, eng, num)
}

// UnseenNotes lists up to limit notes with something new to u, newest
// first, of the engagements u may see that still exist.
func (s *Store) UnseenNotes(u config.User, limit int) ([]Unseen, error) {
	if s.db == nil {
		return nil, nil
	}
	vis, err := s.Visible(u)
	if err != nil {
		return nil, err
	}
	all, err := s.db.UnseenNotes(u.Username, limit)
	if err != nil || len(all) == 0 {
		return nil, err
	}
	ids, err := s.EngagementIDs()
	if err != nil {
		return nil, err
	}
	var out []Unseen
	for _, n := range all {
		if (vis == nil || vis[n.Eng]) && slices.Contains(ids, n.Eng) {
			out = append(out, n)
		}
	}
	return out, nil
}

// UnseenCount is how many of eng's notes have something new to u.
func (s *Store) UnseenCount(u config.User, eng string) (int, error) {
	if s.db == nil {
		return 0, nil
	}
	return s.db.UnseenCount(u.Username, eng)
}
