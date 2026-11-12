package store

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/workflow"
)

// ContentHash identifies a version of finding.md; a clearance counts only
// while the file still has the hash it was given for.
func ContentHash(raw []byte) string { return BodyHash(string(raw)) }

func contentHash(raw []byte) string { return ContentHash(raw) }

// applyState fills the workflow fields of m from st.
func applyState(m *finding.Meta, st db.State, hash string) {
	m.Status, m.Reviewers, m.ClearedBy, m.Returned, m.Withdrawn, m.Retest = st.Status, nil, nil, nil, nil, nil
	if m.Status == "" {
		m.Status = "draft"
	}
	for _, r := range st.Reviewers {
		m.Reviewers = append(m.Reviewers, r.Name)
		if r.ClearedHash != "" && r.ClearedHash == hash {
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
	if (st.Status == "complete" || st.Status == "reported") && !Approved(st, hash) {
		// the content changed after approval without a director's edit
		// through YARS (e.g. a push that raced the approve): review again
		m.Status = "verification"
	}
}

// Approved reports whether st is complete or reported for exactly this
// content (hash of finding.md).
func Approved(st db.State, hash string) bool {
	if st.Status != "complete" && st.Status != "reported" {
		return false
	}
	return st.ApprovedHash == "" || st.ApprovedHash == hash
}

// FindingDirs lists the engagement's finding folders (those holding a
// finding.md, readable or not), sorted, without reading them.
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
	sort.Strings(out)
	return out, nil
}

// ListFindings returns parseable findings of an engagement, sorted by dir.
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
	var out []FindingRef
	for _, e := range ents {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		ref, _, err := s.read(engID, e.Name(), states)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				log.Printf("skip %s/%s: %v", engID, e.Name(), err)
			}
			continue
		}
		out = append(out, ref)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dir < out[j].Dir })
	return out, nil
}

var (
	shortRe  = regexp.MustCompile(`^F-(\d+)(?:-|$)`)
	idOnlyRe = regexp.MustCompile(`^F-(\d+)$`)
)

// ShortID is how a finding appears in URLs: just its number ("001" for
// F-001-sqli). Directories that don't follow the F-<n> scheme keep their name.
func ShortID(dir string) string {
	if m := shortRe.FindStringSubmatch(dir); m != nil {
		return m[1]
	}
	return dir
}

// Finding loads a finding by directory name or by number ("001" or "1"),
// with its workflow state from the database.
func (s *Store) Finding(engID, dir string) (FindingRef, error) {
	ref, _, err := s.read(engID, dir, nil)
	return ref, err
}

// read loads a finding and returns its raw file too. states, when non-nil,
// holds the engagement's stored states (bulk listing); otherwise the
// finding's state is queried.
func (s *Store) read(engID, dir string, states map[string]db.State) (FindingRef, []byte, error) {
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
		return FindingRef{}, nil, fmt.Errorf("%s/%s: %w", engID, dir, err)
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
	hash := contentHash(b)
	applyState(&f.Meta, st, hash)
	ref := FindingRef{EngID: engID, Dir: dir, F: f, Hash: hash}
	if fi, err := s.root.Stat(findingPath(engID, dir)); err == nil {
		ref.Modified = fi.ModTime().UTC()
	}
	return ref, b, nil
}

// attachmentRe is the one name rule for attachments, for listing and
// reading alike: one level, starting with a letter or digit. A ".." inside
// a name ("shot..png") is part of the name and can't leave the folder.
var attachmentRe = regexp.MustCompile(`^attachments/[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ReadAttachment returns a file from the finding's attachments/ folder
// (one level, no dot-files; max 20 MB). Reads go through os.Root.
func (s *Store) ReadAttachment(engID, dir, rel string) ([]byte, error) {
	return s.readAttachment(engID, dir, rel, 20<<20)
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
