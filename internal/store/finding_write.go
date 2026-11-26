package store

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/workflow"
)

// CheckTitle accepts a finding title: one line of 1–200 characters once
// trimmed.
func CheckTitle(title string) error {
	title = strings.TrimSpace(title)
	breaks := strings.ContainsFunc(title, func(r rune) bool {
		// line breaks, line/paragraph separators and terminal controls
		return (unicode.IsControl(r) && r != '\t') || r == ' ' || r == ' '
	})
	if title == "" || breaks || len([]rune(title)) > 200 {
		return fmt.Errorf("%w: the title must be one line of 1–200 characters", ErrInvalidValue)
	}
	return nil
}

// CleanTitle is a title as stored: trimmed, without bidi control characters
// (an override would show "exe.png" for "gnp.exe").
func CleanTitle(title string) string {
	title = strings.Map(func(r rune) rune {
		switch {
		case r >= '‪' && r <= '‮', r >= '⁦' && r <= '⁩', r == '‎', r == '‏', r == '؜':
			return -1
		}
		return r
	}, title)
	return strings.TrimSpace(title)
}

// UpdateTitle changes a finding's title (single line, 1–200 characters).
func (s *Store) UpdateTitle(engID, dir, title string, a Actor) error {
	title = CleanTitle(title)
	if err := ValidTitle(title); err != nil {
		return err
	}
	return s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		return "edit title", f.SetMeta("title", title)
	})
}

var numRe = regexp.MustCompile(`^F-(\d+)`)

func Slug(title string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(title) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = strings.Trim(out[:40], "-")
	}
	if out == "" {
		out = "finding"
	}
	return out
}

func (s *Store) CreateFinding(engID, title string, a gitrepo.Author) (FindingRef, error) {
	title = CleanTitle(title)
	sections := s.Config().Sections
	return s.createFinding(engID, title, a, func(id string) (*finding.Finding, error) {
		return finding.New(id, strings.TrimSpace(title), a.Name, sections), nil
	})
}

// createFinding adds a finding with the next free number; build makes its
// file from that id.
func (s *Store) createFinding(engID, title string, a gitrepo.Author, build func(id string) (*finding.Finding, error)) (FindingRef, error) {
	ref, err := s.createLocked(engID, title, a, build)
	if err != nil {
		return ref, err
	}
	// told once the engagement lock is released: subscribers may read it
	s.Emit(findingEvent(EventCreated, a.Name, ref))
	return ref, nil
}

// createLocked writes and commits the new finding under the engagement lock.
func (s *Store) createLocked(engID, title string, a gitrepo.Author, build func(id string) (*finding.Finding, error)) (FindingRef, error) {
	if err := CheckTitle(title); err != nil {
		return FindingRef{}, err
	}
	if _, err := s.Engagement(engID); err != nil {
		return FindingRef{}, err
	}
	l := s.engLock(engID)
	l.Lock()
	defer l.Unlock()
	if err := s.writable(engID); err != nil { // under the lock, as Archive
		return FindingRef{}, err
	}
	fdir := path.Join(engDir(engID), "findings")
	ents, _ := s.readDir(fdir)
	max := 0
	for _, e := range ents {
		if m := numRe.FindStringSubmatch(e.Name()); m != nil {
			if n, _ := strconv.Atoi(m[1]); n > max {
				max = n
			}
		}
	}
	n := max + 1
	id := fmt.Sprintf("F-%03d", n)
	// never reuse the number of a deleted finding: it would inherit that
	// finding's workflow state and chat
	for s.db != nil {
		known, err := s.db.Known(engID, id)
		if err != nil {
			return FindingRef{}, err
		}
		if !known {
			break
		}
		n++
		id = fmt.Sprintf("F-%03d", n)
	}
	dir := id + "-" + Slug(title)
	f, err := build(id)
	if err != nil {
		return FindingRef{}, err
	}
	if err := s.root.MkdirAll(path.Join(fdir, dir), 0o700); err != nil {
		return FindingRef{}, err
	}
	rel := findingPath(engID, dir)
	if err := s.writeFile(rel, f.Bytes()); err != nil {
		return FindingRef{}, err
	}
	if err := s.commit(map[string][]byte{rel: nil}, id+": create", a, path.Join(fdir, dir)); err != nil {
		return FindingRef{}, err
	}
	return FindingRef{EngID: engID, Dir: dir, F: f}, nil
}

// UpdateSection replaces one section's body and commits. If base is non-empty
// it must equal BodyHash of the section's current body, else ErrConflict.
func (s *Store) UpdateSection(engID, dir, section, body, base string, a Actor) error {
	if section == "" || section != strings.TrimSpace(section) || strings.ContainsAny(section, "\r\n") || strings.HasPrefix(section, "#") {
		return fmt.Errorf("%w: invalid section name %q", ErrInvalidBody, section)
	}
	if err := finding.ValidateBody(body); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidBody, err)
	}
	return s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		cur, ok := f.Section(section)
		if base != "" && BodyHash(cur) != base {
			return "", ErrConflict
		}
		// the text it has, in another layout (a pushed file): nothing to write
		norm := func(t string) string { return strings.Trim(strings.ReplaceAll(t, "\r\n", "\n"), "\n") }
		if !ok || norm(cur) != norm(body) {
			f.SetSection(section, body)
		}
		return "edit " + section, nil
	})
}

// mutateThen loads a finding, applies fn, and commits the result as one
// commit "<ID>: <msg>". No commit is made when the file is unchanged. then
// (may be nil) runs after the commit, still under the engagement's lock,
// with the file's ApprovalHash before and after.
func (s *Store) mutateThen(engID, dir string, a gitrepo.Author, fn func(f *finding.Finding) (string, error), then func(ref FindingRef, oldHash, newHash string) error) error {
	ev, err := s.mutateLocked(engID, dir, a, fn, then)
	if ev.Kind != "" {
		// told once the engagement lock is released: subscribers may read it
		s.Emit(ev)
	}
	return err
}

// mutateLocked does mutateThen's work under the lock and returns the
// finding.updated event once a commit was made.
func (s *Store) mutateLocked(engID, dir string, a gitrepo.Author, fn func(f *finding.Finding) (string, error), then func(ref FindingRef, oldHash, newHash string) error) (Event, error) {
	return s.mutateLockedIn(engID, dir, a, fn, then, false)
}

// mutateLockedIn is mutateLocked; with archived set it writes into an
// archived engagement too (a structure rename keeps every finding readable).
func (s *Store) mutateLockedIn(engID, dir string, a gitrepo.Author, fn func(f *finding.Finding) (string, error), then func(ref FindingRef, oldHash, newHash string) error, archived bool) (Event, error) {
	if !ValidID(engID) {
		return Event{}, ErrNotFound
	}
	l := s.engLock(engID)
	l.Lock()
	defer l.Unlock()
	if err := s.writable(engID); err != nil && !(archived && errors.Is(err, ErrArchived)) { // under the lock, as Archive
		return Event{}, err
	}
	head0, _ := s.freshHead(engID)
	ref, before, err := s.read(engID, dir, nil)
	if err != nil {
		return Event{}, err
	}
	old, _ := finding.Parse(before)
	msg, err := fn(ref.F)
	if err != nil {
		return Event{}, err
	}
	after := ref.F.Bytes()
	// unchanged, or changed only into the canonical layout of what it was
	// (a pushed file's own spacing): no write, and its sign-offs still count
	if string(before) == string(after) || (old != nil && string(old.Bytes()) == string(after)) {
		return Event{}, nil
	}
	if err := s.unmoved(engID, head0); err != nil {
		return Event{}, err
	}
	rel := findingPath(engID, ref.Dir)
	if err := s.writeFile(rel, after); err != nil {
		return Event{}, err
	}
	if err := s.commit(map[string][]byte{rel: before}, ref.F.Meta.ID+": "+msg, a, ""); err != nil {
		return Event{}, err
	}
	defer s.notify(Change{Eng: engID, Fid: ref.F.Meta.ID, Kind: ChangeContent})
	ev := updatedEvent(a.Name, ref, old, false)
	if then != nil {
		return ev, then(ref, ApprovalHash(before), ApprovalHash(after))
	}
	return ev, nil
}

// mutateContent is mutate for content edits by u, refused once the finding
// is locked. Clearances need no reset: they are bound to the content hash,
// so any change of the text voids them (attachments: dropSignOffs).
func (s *Store) mutateContent(engID, dir string, who Actor, fn func(f *finding.Finding) (string, error)) error {
	// the status as read: a front-matter edit (SetMeta) parses the meta
	// again from the file, which holds no workflow state
	status := ""
	return s.mutateThen(engID, dir, who.GitAuthor(), func(f *finding.Finding) (string, error) {
		status = f.Meta.Status
		if u, ok := who.(config.User); ok && !workflow.CanEdit(u, f.Meta) {
			return "", &workflow.Denied{Reason: "this finding is " + f.Meta.Status + "; only a director can edit it"}
		}
		return fn(f)
	}, func(ref FindingRef, oldHash, newHash string) error {
		ref.F.Meta.Status = status
		return s.carryApproval(ref, oldHash, newHash)
	})
}

// carryApproval moves an approval to the new content after an edit of a
// complete or reported finding (allowed for directors only), so the edit
// doesn't send it back to verification. Only an edit of a finding that was
// approved when it was read carries: an approval that raced an edit of an
// open finding stays bound to the content it was given for.
func (s *Store) carryApproval(ref FindingRef, oldHash, newHash string) error {
	if st := ref.F.Meta.Status; st != "complete" && st != "reported" {
		return nil
	}
	return carryApprovalDB(s.db, ref.EngID, ref.F.Meta.ID, oldHash, newHash)
}

// carryApprovalDB moves the approval of eng/fid from oldHash to newHash
// (ApprovalHash values) when the finding was approved for oldHash. Only after the change is in: a
// director's commit through YARS, or a push once it landed (ReceivePush),
// never from the hook.
func carryApprovalDB(d *db.DB, eng, fid, oldHash, newHash string) error {
	if d == nil {
		return nil
	}
	return d.TxFor(eng, func(tx *db.Tx) error {
		st, err := tx.State(eng, fid)
		if err != nil || !Approved(st, oldHash) || st.ApprovedHash == "" {
			return err
		}
		st.ApprovedHash = newHash
		return tx.PutState(eng, fid, st)
	})
}

// signedOff reports whether st is in verification with a sign-off given.
func signedOff(st db.State) bool {
	return st.Status == "verification" && slices.ContainsFunc(st.Reviewers, func(r db.Reviewer) bool { return r.ClearedHash != "" })
}

// dropSignOffs drops the sign-offs of eng/fid while it is in verification
// (used after a change to its attachments, through YARS or by push): a
// sign-off covers them too, but is bound to finding.md's hash, which they
// leave as it is. A complete or reported finding keeps its own.
func dropSignOffs(d *db.DB, eng, fid string) error {
	if d == nil {
		return nil
	}
	return d.TxFor(eng, func(tx *db.Tx) error {
		st, err := tx.State(eng, fid)
		if err != nil || !signedOff(st) {
			return err
		}
		for i := range st.Reviewers {
			st.Reviewers[i].ClearedHash = ""
		}
		return tx.PutState(eng, fid, st)
	})
}
