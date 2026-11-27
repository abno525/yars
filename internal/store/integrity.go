package store

import (
	"errors"
	"io/fs"
	"path"
	"slices"

	"github.com/abno525/yars/internal/finding"
)

// Integrity is what Compare finds between the database and the finding
// files. Every name is "<engagement>/<finding ID>": never a folder's name
// (it holds the title's slug) and never a title.
type Integrity struct {
	Engagements, Findings int // compared

	// By design, so counted and never a fault:

	// NoFinding: IDs with workflow state, reviewers or chat that no folder
	// holds. A pushed deletion leaves them on purpose, so the number is not
	// given to a new finding (db.Known).
	NoFinding []string
	// Drifted: complete or reported findings whose approval is for other
	// text. The pages show them as in verification.
	Drifted []string

	// Faults:

	// Duplicate: an ID two folders of one engagement hold. They share its
	// state, reviewers and chat.
	Duplicate []string
	// Unreadable: a finding.md that does not parse (the ID is the folder's).
	Unreadable []string

	// Set by the start's pass only (Recover): the writes it made from the
	// journal, and the journal rows it could not use.
	Replayed, Unreplayed []string
}

// Faults is the number of things Compare found that should not be.
func (i Integrity) Faults() int { return len(i.Duplicate) + len(i.Unreadable) }

// Compare reads every finding file of every engagement and holds the
// database against it. Each engagement is compared under its lock, its files
// before its rows: a commit and the database write that follows it happen
// under that lock, so Compare never sees the moment between them. It changes
// nothing.
//
// A finding without a state row is a draft and is not reported. A sign-off
// or a check run for other text is the normal result of an edit and is not
// looked at.
func (s *Store) Compare() (Integrity, error) {
	var out Integrity
	if s.db == nil {
		return out, ErrNoDB
	}
	ids, err := s.EngagementIDs()
	if err != nil {
		return out, err
	}
	slices.Sort(ids)
	for _, id := range ids {
		if err := s.compareEngagement(id, &out); err != nil {
			return out, err
		}
	}
	// rows of an engagement that has no folder: the names come from the
	// database and are only looked up, never made into a path
	engs, err := s.db.KnownEngagements()
	if err != nil {
		return out, err
	}
	for _, e := range engs {
		if _, ok := slices.BinarySearch(ids, e); ok {
			continue
		}
		fids, err := s.db.KnownIDs(e)
		if err != nil {
			return out, err
		}
		slices.SortFunc(fids, CompareIDs)
		for _, fid := range fids {
			out.NoFinding = append(out.NoFinding, shownEng(e)+"/"+LogID(fid))
		}
	}
	return out, nil
}

// shownEng is an engagement ID read from the database as a result names it.
func shownEng(id string) string {
	if !ValidID(id) {
		return "?"
	}
	return id
}

// compareEngagement adds one engagement to out, under its lock.
func (s *Store) compareEngagement(id string, out *Integrity) error {
	unlock := s.LockEngagement(id)
	defer unlock()
	out.Engagements++
	ents, err := s.readDir(path.Join(engDir(id), "findings"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	slices.SortFunc(ents, func(a, b fs.DirEntry) int { return CompareIDs(a.Name(), b.Name()) })
	// the files first: finding ID to the ApprovalHash of its file ("" for
	// one that does not parse)
	hashes := map[string]string{}
	for _, e := range ents {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		b, err := s.readFile(findingPath(id, e.Name()))
		if errors.Is(err, fs.ErrNotExist) {
			continue // a folder without a finding.md is no finding
		}
		if err != nil {
			return err
		}
		out.Findings++
		fid, hash := "", ApprovalHash(b)
		if f, err := finding.Parse(b); err != nil {
			fid, hash = LogID(e.Name()), ""
			out.Unreadable = append(out.Unreadable, id+"/"+fid)
		} else {
			fid = f.Meta.ID
		}
		if _, dup := hashes[fid]; dup {
			if name := id + "/" + LogID(fid); !slices.Contains(out.Duplicate, name) {
				out.Duplicate = append(out.Duplicate, name)
			}
			continue // the first folder of the ID is the one the pages read
		}
		hashes[fid] = hash
	}
	// then the rows: a workflow step takes no lock and may land meanwhile; it
	// is then for text at least as new as the file read
	known, err := s.db.KnownIDs(id)
	if err != nil {
		return err
	}
	slices.SortFunc(known, CompareIDs)
	for _, fid := range known {
		if _, ok := hashes[fid]; !ok {
			out.NoFinding = append(out.NoFinding, id+"/"+LogID(fid))
		}
	}
	states, err := s.db.States(id)
	if err != nil {
		return err
	}
	for _, fid := range known {
		st, ok := states[fid]
		hash := hashes[fid]
		if !ok || hash == "" || (st.Status != "complete" && st.Status != "reported") {
			continue
		}
		if !Approved(st, hash) {
			out.Drifted = append(out.Drifted, id+"/"+LogID(fid))
		}
	}
	return nil
}
