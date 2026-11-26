package store

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/workflow"
)

// EngagementIDs lists the engagement folders (sorted), without reading them.
func (s *Store) EngagementIDs() ([]string, error) {
	ents, err := s.readDir("engagements")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.IsDir() && ValidID(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

func (s *Store) ListEngagements() ([]Engagement, error) {
	ids, err := s.EngagementIDs()
	if err != nil {
		return nil, err
	}
	var out []Engagement
	for _, id := range ids {
		eng, err := s.Engagement(id)
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				s.Log().Warn("skip engagement", "eng", id, "err", err)
			}
			continue
		}
		out = append(out, eng)
	}
	return out, nil
}

func (s *Store) Engagement(id string) (Engagement, error) {
	if !ValidID(id) {
		return Engagement{}, ErrNotFound
	}
	b, err := s.readFile(path.Join(engDir(id), "engagement.yaml"))
	if errors.Is(err, fs.ErrNotExist) {
		return Engagement{}, ErrNotFound
	}
	if err != nil {
		return Engagement{}, err
	}
	e, err := ParseEngagement(b)
	if err != nil {
		return Engagement{}, fmt.Errorf("engagement %s: %w", id, err)
	}
	e.ID = id
	e.Archived = s.Archived(id)
	return e, nil
}

// ParseEngagement reads an engagement.yaml.
func ParseEngagement(b []byte) (Engagement, error) {
	var e Engagement
	err := yaml.Unmarshal(b, &e)
	return e, err
}

func (s *Store) CreateEngagement(e Engagement, a gitrepo.Author) error {
	if !ValidID(e.ID) {
		return fmt.Errorf("invalid engagement id %q", e.ID)
	}
	if s.rootErr != nil {
		return s.rootErr
	}
	unlock := s.lockNew(e.ID)
	defer unlock()
	dir := engDir(e.ID)
	if _, err := s.root.Lstat(dir); err == nil {
		return fmt.Errorf("engagement %s already exists", e.ID)
	}
	if e.Type == "" {
		e.Type = "pentest"
	}
	b, err := yaml.Marshal(e)
	if err != nil {
		return err
	}
	if err := s.root.MkdirAll(path.Join(dir, "findings"), 0o700); err != nil {
		return err
	}
	if err := s.writeFile(path.Join(dir, "engagement.yaml"), b); err != nil {
		s.root.RemoveAll(dir)
		return err
	}
	if err := s.newEngagementRepo(e.ID, []string{"engagement.yaml"}, "engagement "+e.ID+": create", a); err != nil {
		return err
	}
	return s.purge(e.ID)
}

// purge drops leftover state and chat of a deleted engagement with the same
// id, so a new engagement never inherits them.
func (s *Store) purge(engID string) error {
	if s.db == nil {
		return nil
	}
	return s.db.TxFor(engID, func(tx *db.Tx) error { return tx.Purge(engID) })
}

// CreateRetest creates engagement e (type retest) from source, copying the
// findings in dirs as fresh drafts with a retest link. The source engagement
// is never modified. One commit; only directors.
//
// assignee becomes the author of every copy (the retester); "" keeps each
// finding's original author.
func (s *Store) CreateRetest(e Engagement, source string, dirs []string, assignee string, u config.User) error {
	dirs = slices.Compact(slices.Sorted(slices.Values(dirs)))
	if !workflow.AtLeast(u, "director") {
		return &workflow.Denied{Reason: "only a director can start a retest"}
	}
	if !ValidID(e.ID) {
		return fmt.Errorf("%w: invalid engagement id %q", ErrInvalidValue, e.ID)
	}
	if strings.TrimSpace(e.Name) == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidValue)
	}
	if len(dirs) == 0 {
		return fmt.Errorf("%w: select at least one finding", ErrInvalidValue)
	}
	if _, err := s.Engagement(source); err != nil {
		return err
	}
	if s.rootErr != nil {
		return s.rootErr
	}
	if s.db == nil { // the links to the originals and the team live there
		return ErrNoDB
	}
	unlock := s.lockNew(e.ID)
	defer unlock()
	dir := engDir(e.ID)
	if _, err := s.root.Lstat(dir); err == nil {
		return fmt.Errorf("%w: engagement %s already exists", ErrInvalidValue, e.ID)
	}
	type copyOf struct {
		dir     string
		f       *finding.Finding
		attachs []string // its attachments' names (each read as it is written)
	}
	var copies []copyOf
	for _, d := range dirs {
		ref, err := s.Finding(source, d)
		if err != nil {
			return fmt.Errorf("%w: finding %s: %v", ErrInvalidValue, d, err)
		}
		if !workflow.Active(ref.F.Meta.Status) {
			return fmt.Errorf("%w: finding %s is withdrawn", ErrInvalidValue, d)
		}
		f := ref.F
		if assignee != "" {
			if err := f.SetMeta("author", assignee); err != nil {
				return err
			}
		}
		as, err := s.AttachmentsOf(ref)
		if err != nil {
			return err
		}
		c := copyOf{d, f, nil}
		for _, a := range as {
			if a.Size > maxRead { // ReadAttachment would not read it
				return fmt.Errorf("%w: finding %s: attachment %s is larger than %d MB", ErrInvalidValue, d, a.Name, maxRead>>20)
			}
			c.attachs = append(c.attachs, a.Name)
		}
		copies = append(copies, c)
	}
	e.Type, e.Source = "retest", source
	b, err := yaml.Marshal(e)
	if err != nil {
		return err
	}
	// The links and the team first, the repository after, the links taken
	// back if it fails: a retest is whole or not there, never copies that
	// look like plain drafts.
	links := make([][2]string, len(copies)) // each copy's finding ID and folder
	for i, c := range copies {
		links[i] = [2]string{c.f.Meta.ID, c.dir}
	}
	if err := s.retestLinks(e.ID, source, assignee, links); err != nil {
		return err
	}
	fail := func(err error) error {
		s.root.RemoveAll(dir)
		s.db.TxFor(e.ID, func(tx *db.Tx) error { return tx.Purge(e.ID) })
		return err
	}
	var files []string // relative to the new engagement repo
	write := func(rel string, data []byte) error {
		p := path.Join(dir, rel)
		if err := s.root.MkdirAll(path.Dir(p), 0o700); err != nil {
			return err
		}
		files = append(files, rel)
		return s.writeFile(p, data)
	}
	if err := write("engagement.yaml", b); err != nil {
		return fail(err)
	}
	for _, c := range copies {
		if err := write(path.Join("findings", c.dir, "finding.md"), c.f.Bytes()); err != nil {
			return fail(err)
		}
		for _, name := range c.attachs { // one in memory at a time
			data, err := s.ReadAttachment(source, c.dir, "attachments/"+name)
			if err != nil {
				return fail(err)
			}
			if err := write(path.Join("findings", c.dir, "attachments", name), data); err != nil {
				return fail(err)
			}
		}
	}
	msg := fmt.Sprintf("engagement %s: retest of %s (%d findings)", e.ID, source, len(copies))
	if err := s.newEngagementRepo(e.ID, files, msg, u.GitAuthor()); err != nil {
		s.db.TxFor(e.ID, func(tx *db.Tx) error { return tx.Purge(e.ID) })
		return err
	}
	return nil
}

// retestsOf lists the retests made from engID and the retests of those,
// nearest first (engagement.yaml's source).
func (s *Store) retestsOf(engID string) ([]Engagement, error) {
	engs, err := s.ListEngagements()
	if err != nil {
		return nil, err
	}
	var out []Engagement
	seen := map[string]bool{engID: true}
	for queue := []string{engID}; len(queue) > 0; queue = queue[1:] {
		for _, e := range engs {
			if e.Type != "retest" || e.Source != queue[0] || seen[e.ID] {
				continue
			}
			seen[e.ID] = true
			queue = append(queue, e.ID)
			out = append(out, e)
		}
	}
	return out, nil
}

// copyIn is retest e's copy of finding fid: the finding with that ID whose
// retest link names the engagement e was made from. ok is false when there
// is none (deleted since, say).
func (s *Store) copyIn(e Engagement, fid string) (ref FindingRef, ok bool) {
	ref, err := s.Finding(e.ID, fid)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			s.Log().Error("retest copy not read", "eng", e.ID, "finding", fid, "err", err)
		}
		return FindingRef{}, false
	}
	rt := ref.F.Meta.Retest
	return ref, ref.F.Meta.ID == fid && rt != nil && strings.HasPrefix(rt.Source, e.Source+"/")
}

// retestCopies lists the copies of finding fid of engID in the retests
// made from engID and in the retests of those, nearest first (copyIn). A
// retest whose copy is gone is passed over, not its own retests.
func (s *Store) retestCopies(engID, fid string) ([]FindingRef, error) {
	rts, err := s.retestsOf(engID)
	if err != nil {
		return nil, err
	}
	var out []FindingRef
	for _, e := range rts {
		if ref, ok := s.copyIn(e, fid); ok {
			out = append(out, ref)
		}
	}
	return out, nil
}

// retestLinks writes a retest's team (the source's, with the retester) and
// each copy's state (its finding ID and source folder): a fresh draft that
// links to its original.
func (s *Store) retestLinks(id, source, assignee string, copies [][2]string) error {
	return s.db.TxFor(id, func(tx *db.Tx) error {
		if err := tx.Purge(id); err != nil {
			return err
		}
		// the source's team works on the retest, with the retester
		team, err := tx.Members(source)
		if err != nil {
			return err
		}
		if assignee != "" {
			team = append(team, assignee)
		}
		if err := tx.AddMembers(id, team...); err != nil {
			return err
		}
		for _, c := range copies {
			if err := tx.PutState(id, c[0], db.State{Status: "draft", RetestSource: source + "/" + c[1]}); err != nil {
				return err
			}
		}
		return nil
	})
}
