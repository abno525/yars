package store

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/workflow"
)

// ContentHash identifies a version of finding.md; a clearance counts only
// while the file still has the hash it was given for.
func ContentHash(raw []byte) string { return BodyHash(string(raw)) }

func contentHash(raw []byte) string { return ContentHash(raw) }

// ApprovalHash is what an approval and a sign-off are bound to, and with
// them what the deciding page says it showed (TransitionSeen) and what a
// check run is kept under: the full SHA-256 of finding.md, in hex.
// ContentHash is its first 16 digits; 64 bits tell versions apart (edit
// bases) but two files can be made to share them, so they bind no decision.
func ApprovalHash(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// boundTo reports whether an approval or a sign-off stored as stored is for
// the content whose ApprovalHash is full. A stored value of 16 digits is from
// before the full digest was kept: it counts for the content whose digest
// starts with it, with the 64 bits it always had, until the finding is
// signed off or approved again (or a director's edit carries it), which
// stores the full digest. Without this every complete and reported finding
// would fall back to verification at the upgrade.
func boundTo(stored, full string) bool {
	return stored == full || len(stored) == 16 && len(full) > 16 && strings.HasPrefix(full, stored)
}

// applyState fills the workflow fields of m from st, as workflow f reads
// it; hash is the ApprovalHash of the finding's file. The simple workflow
// has no verification and no reviewers: a stored verification, and a
// complete or reported finding whose content changed after its approval,
// read as draft, and stored reviewers are left out.
func applyState(m *finding.Meta, st db.State, hash string, f workflow.Flow) {
	m.Status, m.Reviewers, m.ClearedBy, m.Returned, m.Withdrawn, m.Retest = st.Status, nil, nil, nil, nil, nil
	if m.Status == "" {
		m.Status = "draft"
	}
	for _, r := range st.Reviewers {
		m.Reviewers = append(m.Reviewers, r.Name)
		if r.ClearedHash != "" && boundTo(r.ClearedHash, hash) {
			m.ClearedBy = append(m.ClearedBy, r.Name)
		}
	}
	if st.ReturnedBy != "" {
		m.Returned = &finding.Returned{By: st.ReturnedBy, Reason: st.ReturnedReason}
	}
	if st.Status == workflow.Withdrawn {
		m.Withdrawn = &finding.Returned{By: st.WithdrawnBy, Reason: st.WithdrawnReason}
	}
	if st.RetestSource != "" {
		m.Retest = &finding.Retest{Source: st.RetestSource, Result: st.RetestResult}
	}
	drifted := (st.Status == "complete" || st.Status == "reported") && !Approved(st, hash)
	if f.Simple {
		// nothing to review: a drifted finding is completed again
		if drifted || st.Status == "verification" {
			m.Status = "draft"
		}
		m.Reviewers, m.ClearedBy = nil, nil
		return
	}
	if drifted {
		// the content changed after approval without a director's edit
		// through YARS (e.g. a push that raced the approve): review again
		m.Status = "verification"
	}
}

// Approved reports whether st is complete or reported for exactly this
// content (the ApprovalHash of finding.md).
func Approved(st db.State, hash string) bool {
	if st.Status != "complete" && st.Status != "reported" {
		return false
	}
	return st.ApprovedHash == "" || boundTo(st.ApprovedHash, hash)
}

// FindingDirs lists the engagement's finding folders (those holding a
// finding.md, readable or not), in the order of CompareIDs, without reading
// them.
func (s *Store) FindingDirs(engID string) ([]string, error) {
	if _, err := s.Engagement(engID); err != nil {
		return nil, err
	}
	ents, err := s.readDir(path.Join(engDir(engID), "findings"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		if _, err := s.root.Stat(findingPath(engID, e.Name())); err == nil {
			out = append(out, e.Name())
		}
	}
	slices.SortFunc(out, CompareIDs)
	return out, nil
}

// ListFindings returns parseable findings of an engagement, sorted by dir
// (CompareIDs: by number).
// Unparseable finding files are logged and skipped so one bad local edit
// cannot hide the whole table.
func (s *Store) ListFindings(engID string) ([]FindingRef, error) {
	if _, err := s.Engagement(engID); err != nil {
		return nil, err
	}
	ents, err := s.readDir(path.Join(engDir(engID), "findings"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	states := map[string]db.State{}
	if s.db != nil {
		if states, err = s.db.States(engID); err != nil {
			return nil, err
		}
	}
	noAI := s.noAI(engID) // read once for the list
	var out []FindingRef
	for _, e := range ents {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		ref, _, err := s.readAs(engID, e.Name(), states, &noAI)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				// the folder's name holds the title's slug: the ID only
				s.Log().Warn("skip finding", "eng", engID, "finding", LogID(e.Name()), "err", err)
			}
			continue
		}
		out = append(out, ref)
	}
	slices.SortFunc(out, func(a, b FindingRef) int { return CompareIDs(a.Dir, b.Dir) })
	return out, nil
}

var (
	shortRe  = regexp.MustCompile(`^F-(\d+)(?:-|$)`)
	idOnlyRe = regexp.MustCompile(`^F-(\d+)$`)
)

// CompareIDs orders finding IDs and folder names (F-7, F-012-xss) by their
// number, then by the whole name: F-999 is before F-1000. Names outside the
// F-<n> scheme come after those, by name. The number is compared as digits,
// so no length of it overflows.
func CompareIDs(a, b string) int {
	na, oka := idDigits(a)
	nb, okb := idDigits(b)
	switch {
	case !oka && !okb:
		return strings.Compare(a, b)
	case !oka:
		return 1
	case !okb:
		return -1
	}
	if c := cmp.Compare(len(na), len(nb)); c != 0 {
		return c
	}
	if c := strings.Compare(na, nb); c != 0 {
		return c
	}
	return strings.Compare(a, b)
}

// idDigits is the number of a name in the F-<n> scheme (as shortRe reads
// it), without its leading zeros.
func idDigits(s string) (string, bool) {
	rest, ok := strings.CutPrefix(s, "F-")
	if !ok {
		return "", false
	}
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 || (i < len(rest) && rest[i] != '-') {
		return "", false
	}
	return strings.TrimLeft(rest[:i], "0"), true
}

// ShortID is how a finding appears in URLs: just its number ("001" for
// F-001-sqli). Directories that don't follow the F-<n> scheme keep their name.
func ShortID(dir string) string {
	if m := shortRe.FindStringSubmatch(dir); m != nil {
		return m[1]
	}
	return dir
}

var logNumRe = regexp.MustCompile(`^\d{1,9}$`)

// LogID is a finding as a log line names it: its ID alone, "F-001" for the
// folder F-001-sql-injection, the ID F-001 or the number 001. The rest of a
// folder's name is a slug of the title, which no log line holds; a name that
// is none of the three is "?".
func LogID(dir string) string {
	if m := shortRe.FindStringSubmatch(dir); m != nil && len(m[1]) <= 9 {
		return "F-" + m[1]
	}
	if logNumRe.MatchString(dir) {
		return "F-" + dir
	}
	return "?"
}

// Finding loads a finding by directory name or by number ("001" or "1"),
// with its workflow state from the database.
func (s *Store) Finding(engID, dir string) (FindingRef, error) {
	ref, _, err := s.read(engID, dir, nil)
	return ref, err
}

// read loads a finding and returns its raw file too. states, when non-nil,
// holds the engagement's stored states (bulk listing); otherwise the
// finding's state is queried. The finding's Meta says where it is: its
// engagement and whether that engagement takes no AI, read from
// engagement.yaml now.
func (s *Store) read(engID, dir string, states map[string]db.State) (FindingRef, []byte, error) {
	return s.readAs(engID, dir, states, nil)
}

// readAs is read; noAI, when non-nil, is the engagement's AI switch as the
// caller read it (a listing reads it once).
func (s *Store) readAs(engID, dir string, states map[string]db.State, noAI *bool) (FindingRef, []byte, error) {
	if !ValidID(engID) || !ValidID(dir) {
		return FindingRef{}, nil, ErrNotFound
	}
	if m := idOnlyRe.FindStringSubmatch(dir); m != nil {
		// an ID (F-013) names the folder of that number, unless a folder
		// is called just that
		if _, err := s.root.Stat(path.Join(engDir(engID), "findings", dir)); err != nil {
			dir = m[1]
		}
	}
	if n, err := strconv.Atoi(dir); err == nil && strings.Trim(dir, "0123456789") == "" {
		ents, _ := s.readDir(path.Join(engDir(engID), "findings"))
		dir = ""
		for _, e := range ents {
			if m := shortRe.FindStringSubmatch(e.Name()); m != nil && e.IsDir() {
				if k, _ := strconv.Atoi(m[1]); k == n && n > 0 {
					dir = e.Name()
					break
				}
			}
		}
		if dir == "" {
			return FindingRef{}, nil, ErrNotFound
		}
	}
	b, err := s.readFile(findingPath(engID, dir))
	if errors.Is(err, fs.ErrNotExist) {
		return FindingRef{}, nil, ErrNotFound
	}
	if err != nil {
		return FindingRef{}, nil, err
	}
	f, err := finding.Parse(b)
	if err != nil {
		return FindingRef{}, nil, &UnreadableError{Eng: engID, Dir: dir, Err: err}
	}
	// a title pushed over git can still hold bidi controls: never show them
	f.Meta.Title = CleanTitle(f.Meta.Title)
	st := db.State{Status: "draft"}
	if s.db != nil {
		if states != nil {
			if got, ok := states[f.Meta.ID]; ok {
				st = got
			}
		} else if st, err = s.db.State(engID, f.Meta.ID); err != nil {
			return FindingRef{}, nil, err
		}
	}
	full := ApprovalHash(b)
	applyState(&f.Meta, st, full, s.Flow())
	if f.Meta.Engagement = engID; noAI != nil {
		f.Meta.NoAI = *noAI
	} else {
		f.Meta.NoAI = s.noAI(engID)
	}
	ref := FindingRef{EngID: engID, Dir: dir, F: f, Hash: contentHash(b), Full: full}
	if fi, err := s.root.Stat(findingPath(engID, dir)); err == nil {
		ref.Modified = fi.ModTime().UTC()
	}
	return ref, b, nil
}

// attachmentRe is the one name rule for attachments, for listing and
// reading alike: one level, starting with a letter or digit. A ".." inside
// a name ("shot..png") is part of the name and can't leave the folder.
var attachmentRe = regexp.MustCompile(`^attachments/[A-Za-z0-9][A-Za-z0-9._-]*$`)

// maxRead is the largest attachment ReadAttachment reads (an upload is at
// most MaxAttachment; only a hand edit makes a larger one).
const maxRead = 20 << 20

// ReadAttachment returns a file from the finding's attachments/ folder
// (one level, no dot-files; max 20 MB). Reads go through os.Root.
func (s *Store) ReadAttachment(engID, dir, rel string) ([]byte, error) {
	return s.readAttachment(engID, dir, rel, maxRead)
}

// readAttachment is ReadAttachment with a size cap (0: none).
func (s *Store) readAttachment(engID, dir, rel string, max int64) ([]byte, error) {
	if !ValidID(engID) || !ValidID(dir) || !attachmentRe.MatchString(rel) {
		return nil, ErrNotFound
	}
	p := path.Join("engagements", engID, "findings", dir, rel)
	if s.rootErr != nil {
		return nil, s.rootErr
	}
	info, err := s.root.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || (max > 0 && info.Size() > max) {
		return nil, ErrNotFound
	}
	return s.readFile(p)
}
