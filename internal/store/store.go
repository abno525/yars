// Package store maps the data repo layout to engagements and findings.
// Content (finding.md, attachments) lives in git: every content write is a
// single commit. Workflow state and chat live in the YARS database. All file
// access goes through an os.Root so symlinks cannot reach outside the
// repository.
package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/cvss"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/rules"
	"yars/internal/workflow"
)

var (
	ErrNotFound    = errors.New("not found")
	ErrConflict    = errors.New("section was changed by someone else")
	ErrInvalidBody = errors.New("invalid section body")
	// ErrInvalidValue marks a rejected front-matter value (CVSS vector, severity).
	ErrInvalidValue = errors.New("invalid value")
	// ErrNoDB: workflow and chat need the YARS database, which only the server
	// has (a local clone holds content only).
	ErrNoDB = errors.New("workflow state and chat are kept on the YARS server; use its web UI or its /mcp endpoint")
)

type Engagement struct {
	ID     string `yaml:"-"`
	Name   string `yaml:"name"`
	Client string `yaml:"client"`
	Type   string `yaml:"type"`
	Source string `yaml:"source,omitempty"`
	Start  string `yaml:"start,omitempty"`
	End    string `yaml:"end,omitempty"`
}

type FindingRef struct {
	EngID, Dir string
	F          *finding.Finding
}

type Store struct {
	repo    *gitrepo.Repo
	db      *db.DB // nil on a local clone: content only
	cfg     config.Config
	root    *os.Root
	rootErr error
	mu      sync.Mutex

	// Linter, when set, runs the style rules; error-level violations block
	// submit and approve.
	Linter Linter

	beforeWrite func() // test hook: runs between reading and writing
}

// errMoved is returned when HEAD moved (e.g. a git push landed) between
// reading a finding and writing it; the caller should reload and retry.
var errMoved = fmt.Errorf("%w: the repository changed meanwhile (a push arrived); reload and try again", ErrConflict)

// unmoved reports whether HEAD is still head0.
func (s *Store) unmoved(head0 string) error {
	if s.beforeWrite != nil {
		s.beforeWrite()
	}
	if h, err := s.repo.Head(); err != nil || h != head0 {
		return errMoved
	}
	return nil
}

type Linter interface {
	Lint(ctx context.Context, f *finding.Finding, kinds rules.Kind) []rules.Violation
}

// New opens the store on repo r. d holds workflow state and chat; nil means
// content only (state reads as draft, state and chat writes return ErrNoDB).
func New(r *gitrepo.Repo, cfg config.Config, d *db.DB) *Store {
	root, err := os.OpenRoot(r.Dir)
	return &Store{repo: r, db: d, cfg: cfg, root: root, rootErr: err}
}

// DB is the database (nil on a local clone).
func (s *Store) DB() *db.DB { return s.db }

// contentHash identifies a version of finding.md; a clearance counts only
// while the file still has the hash it was given for.
func contentHash(raw []byte) string { return BodyHash(string(raw)) }

// applyState fills the workflow fields of m from st.
func applyState(m *finding.Meta, st db.State, hash string) {
	m.Status, m.Reviewers, m.ClearedBy, m.Returned, m.Retest = st.Status, nil, nil, nil, nil
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
	if st.RetestSource != "" {
		m.Retest = &finding.Retest{Source: st.RetestSource, Result: st.RetestResult}
	}
}

func (s *Store) Config() config.Config { return s.cfg }
func (s *Store) Repo() *gitrepo.Repo   { return s.repo }

var idRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// ValidID accepts path-safe names; leading dots (".", "..", ".git") are rejected.
func ValidID(id string) bool { return idRe.MatchString(id) && !strings.HasPrefix(id, ".") }

// BodyHash identifies a section body version for optimistic concurrency.
func BodyHash(body string) string {
	h := sha256.Sum256([]byte(body))
	return hex.EncodeToString(h[:8])
}

func engDir(id string) string { return path.Join("engagements", id) }
func findingPath(eng, dir string) string {
	return path.Join("engagements", eng, "findings", dir, "finding.md")
}

func (s *Store) readDir(p string) ([]fs.DirEntry, error) {
	if s.rootErr != nil {
		return nil, s.rootErr
	}
	return fs.ReadDir(s.root.FS(), p)
}

func (s *Store) readFile(p string) ([]byte, error) {
	if s.rootErr != nil {
		return nil, s.rootErr
	}
	return s.root.ReadFile(p)
}

func (s *Store) writeFile(p string, b []byte) error {
	if s.rootErr != nil {
		return s.rootErr
	}
	return s.root.WriteFile(p, b, 0o644)
}

func (s *Store) ListEngagements() ([]Engagement, error) {
	ents, err := s.readDir("engagements")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Engagement
	for _, e := range ents {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		eng, err := s.Engagement(e.Name())
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				log.Printf("skip engagement %s: %v", e.Name(), err)
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
	var e Engagement
	if err := yaml.Unmarshal(b, &e); err != nil {
		return Engagement{}, fmt.Errorf("engagement %s: %w", id, err)
	}
	e.ID = id
	return e, nil
}

// commit commits paths; on failure it restores each path's previous content
// (nil = file did not exist) so the tree is left clean.
func (s *Store) commit(prev map[string][]byte, msg string, a gitrepo.Author, cleanupDir string) error {
	var paths []string
	for p := range prev {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	err := s.repo.Commit(paths, msg, a)
	if err == nil {
		return nil
	}
	s.repo.Unstage(paths)
	for _, p := range paths {
		if prev[p] == nil {
			s.root.Remove(p)
		} else {
			s.writeFile(p, prev[p])
		}
	}
	if cleanupDir != "" {
		s.root.RemoveAll(cleanupDir)
	}
	return err
}

func (s *Store) CreateEngagement(e Engagement, a gitrepo.Author) error {
	if !ValidID(e.ID) {
		return fmt.Errorf("invalid engagement id %q", e.ID)
	}
	if s.rootErr != nil {
		return s.rootErr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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
	if err := s.root.MkdirAll(path.Join(dir, "findings"), 0o755); err != nil {
		return err
	}
	rel := path.Join(dir, "engagement.yaml")
	if err := s.writeFile(rel, b); err != nil {
		s.root.RemoveAll(dir)
		return err
	}
	return s.commit(map[string][]byte{rel: nil}, "engagement "+e.ID+": create", a, dir)
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
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := engDir(e.ID)
	if _, err := s.root.Lstat(dir); err == nil {
		return fmt.Errorf("%w: engagement %s already exists", ErrInvalidValue, e.ID)
	}
	type copyOf struct {
		dir string
		f   *finding.Finding
	}
	var copies []copyOf
	for _, d := range dirs {
		ref, err := s.Finding(source, d)
		if err != nil {
			return fmt.Errorf("%w: finding %s: %v", ErrInvalidValue, d, err)
		}
		f := ref.F
		if assignee != "" {
			if err := f.SetMeta("author", assignee); err != nil {
				return err
			}
		}
		copies = append(copies, copyOf{d, f})
	}
	e.Type, e.Source = "retest", source
	b, err := yaml.Marshal(e)
	if err != nil {
		return err
	}
	prev := map[string][]byte{}
	write := func(rel string, data []byte) error {
		if err := s.root.MkdirAll(path.Dir(rel), 0o755); err != nil {
			return err
		}
		prev[rel] = nil
		return s.writeFile(rel, data)
	}
	if err := write(path.Join(dir, "engagement.yaml"), b); err != nil {
		s.root.RemoveAll(dir)
		return err
	}
	for _, c := range copies {
		if err := write(findingPath(e.ID, c.dir), c.f.Bytes()); err != nil {
			s.root.RemoveAll(dir)
			return err
		}
	}
	msg := fmt.Sprintf("engagement %s: retest of %s (%d findings)", e.ID, source, len(copies))
	if err := s.commit(prev, msg, u.GitAuthor(), dir); err != nil {
		return err
	}
	if s.db == nil {
		return nil
	}
	// each copy starts as a fresh draft that links to the original
	return s.db.Tx(func(tx *db.Tx) error {
		for _, c := range copies {
			if err := tx.PutState(e.ID, c.f.Meta.ID, db.State{Status: "draft", RetestSource: source + "/" + c.dir}); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpdateTitle changes a finding's title (single line, 1–200 characters).
func (s *Store) UpdateTitle(engID, dir, title string, a Actor) error {
	title = strings.TrimSpace(title)
	if title == "" || strings.ContainsAny(title, "\r\n") || len([]rune(title)) > 200 {
		return fmt.Errorf("%w: the title must be one line of 1–200 characters", ErrInvalidValue)
	}
	return s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		return "edit title", f.SetMeta("title", title)
	})
}

// SetRetestResult records the outcome of a retested finding (database).
func (s *Store) SetRetestResult(engID, dir, result string, a Actor) error {
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
		st.RetestResult = result
		return nil, nil
	})
}

// changeState loads a finding and its state under the store lock, lets fn
// change the state, and stores it — with any workflow events fn returns —
// in one database transaction. No git commit is made.
func (s *Store) changeState(engID, dir string, fn func(ref FindingRef, st *db.State, hash string) ([]chat.Message, error)) error {
	if s.db == nil {
		return ErrNoDB
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, raw, err := s.read(engID, dir, nil)
	if err != nil {
		return err
	}
	fid := ref.F.Meta.ID
	st, err := s.db.State(engID, fid)
	if err != nil {
		return err
	}
	msgs, err := fn(ref, &st, contentHash(raw))
	if err != nil {
		return err
	}
	return s.db.Tx(func(tx *db.Tx) error {
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

var shortRe = regexp.MustCompile(`^F-(\d+)(?:-|$)`)

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
	applyState(&f.Meta, st, contentHash(b))
	return FindingRef{EngID: engID, Dir: dir, F: f}, b, nil
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
	if _, err := s.Engagement(engID); err != nil {
		return FindingRef{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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
	id := fmt.Sprintf("F-%03d", max+1)
	dir := id + "-" + Slug(title)
	f := finding.New(id, strings.TrimSpace(title), a.Name, s.cfg.Sections)
	if err := s.root.MkdirAll(path.Join(fdir, dir), 0o755); err != nil {
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
		if base != "" {
			cur, _ := f.Section(section)
			if BodyHash(cur) != base {
				return "", ErrConflict
			}
		}
		f.SetSection(section, body)
		return "edit " + section, nil
	})
}

// mutate loads a finding, applies fn, and commits the result as one commit
// "<ID>: <msg>". No commit is made when the file is unchanged.
func (s *Store) mutate(engID, dir string, a gitrepo.Author, fn func(f *finding.Finding) (string, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	head0, _ := s.repo.Head()
	ref, before, err := s.read(engID, dir, nil)
	if err != nil {
		return err
	}
	msg, err := fn(ref.F)
	if err != nil {
		return err
	}
	after := ref.F.Bytes()
	if string(before) == string(after) {
		return nil
	}
	if err := s.unmoved(head0); err != nil {
		return err
	}
	rel := findingPath(engID, ref.Dir)
	if err := s.writeFile(rel, after); err != nil {
		return err
	}
	return s.commit(map[string][]byte{rel: before}, ref.F.Meta.ID+": "+msg, a, "")
}

var attachmentRe = regexp.MustCompile(`^attachments/[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ReadAttachment returns a file from the finding's attachments/ folder
// (one level, no dot-files; max 20 MB). Reads go through os.Root.
func (s *Store) ReadAttachment(engID, dir, rel string) ([]byte, error) {
	if !ValidID(engID) || !ValidID(dir) || !attachmentRe.MatchString(rel) || strings.Contains(rel, "..") {
		return nil, ErrNotFound
	}
	p := path.Join("engagements", engID, "findings", dir, rel)
	if s.rootErr != nil {
		return nil, s.rootErr
	}
	info, err := s.root.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 20<<20 {
		return nil, ErrNotFound
	}
	return s.readFile(p)
}

// Chat returns the finding's chat messages and workflow events (empty when
// none, or without a database).
func (s *Store) Chat(engID, dir string) ([]chat.Message, error) {
	ref, err := s.Finding(engID, dir)
	if err != nil || s.db == nil {
		return nil, err
	}
	return s.db.Messages(engID, ref.F.Meta.ID)
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

// PostChat validates and stores a message as u (database, no commit). ID,
// time and user are filled in; the returned message is what was stored.
func (s *Store) PostChat(engID, dir string, m chat.Message, u config.User) (chat.Message, error) {
	m.ID, m.TS, m.User, m.Event = chat.NewID(), time.Now().UTC().Truncate(time.Second), u.Username, ""
	m.Text = strings.TrimSpace(m.Text)
	if m.Resolves != "" || m.Reopens != "" {
		m.Text, m.Section = "", "" // markers carry no content
	}
	if s.db == nil {
		return m, ErrNoDB
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return m, err
	}
	if m.Section != "" {
		if _, ok := ref.F.Section(m.Section); !ok && !slices.Contains(s.cfg.Sections, m.Section) {
			return m, fmt.Errorf("%w: unknown section %q", ErrInvalidChat, m.Section)
		}
	}
	existing, err := s.db.Messages(engID, ref.F.Meta.ID)
	if err != nil {
		return m, err
	}
	if err := chat.Validate(existing, m); err != nil {
		return m, fmt.Errorf("%w: %v", ErrInvalidChat, err)
	}
	return m, s.db.Tx(func(tx *db.Tx) error { return tx.AddMessage(engID, ref.F.Meta.ID, m) })
}

// mutateContent is mutate for content edits by u, refused once the finding
// is locked. Clearances need no reset: they are bound to the content hash,
// so any change voids them.
func (s *Store) mutateContent(engID, dir string, who Actor, fn func(f *finding.Finding) (string, error)) error {
	return s.mutate(engID, dir, who.GitAuthor(), func(f *finding.Finding) (string, error) {
		if u, ok := who.(config.User); ok && !workflow.CanEdit(u, f.Meta) {
			return "", &workflow.Denied{Reason: "this finding is " + f.Meta.Status + "; only a director can edit it"}
		}
		return fn(f)
	})
}

// AuthorOf maps an account to its git identity.
func AuthorOf(u config.User) gitrepo.Author { return u.GitAuthor() }

// Actor performs a content edit. A config.User is permission-checked against
// the freshly loaded finding (workflow.CanEdit) inside the store lock; a bare
// gitrepo.Author is a trusted internal caller (tools, tests) and is not.
type Actor interface{ GitAuthor() gitrepo.Author }

// Transition applies a workflow action as u: the state changes in the
// database together with a workflow event in the chat (no git commit).
// Permission and gate failures are *workflow.Denied.
func (s *Store) Transition(engID, dir string, act workflow.Action, reason string, u config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	// Style rules (scripts, AI) can be slow, so they run outside the lock on
	// a snapshot; the change is refused if the finding changed meanwhile.
	linted := ""
	if workflow.Gated(act) && s.Linter != nil {
		ref, raw, err := s.read(engID, dir, nil)
		if err != nil {
			return err
		}
		if err := workflow.CheckWithGate(u, ref.F.Meta, act, s.cfg); err != nil {
			return err
		}
		if errs := rules.Errors(s.Linter.Lint(context.Background(), ref.F, rules.All)); len(errs) > 0 {
			return &workflow.Denied{Reason: "cannot " + strings.ToLower(workflow.Label(act)) + ": " + strings.Join(errs, "; ")}
		}
		linted = contentHash(raw)
	}
	return s.changeState(engID, dir, func(ref FindingRef, st *db.State, hash string) ([]chat.Message, error) {
		if linted != "" && hash != linted {
			return nil, &workflow.Denied{Reason: "the finding changed while its checks ran; try again"}
		}
		if err := workflow.CheckWithGate(u, ref.F.Meta, act, s.cfg); err != nil {
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
			uncleared()
		}
		_, st.Status = workflow.Target(act)
		return []chat.Message{ev}, nil
	})
}

// SetReviewers replaces the reviewer list as u. The author is never a
// reviewer; clearances of reviewers who stay are kept.
func (s *Store) SetReviewers(engID, dir string, names []string, u config.User) error {
	return s.changeState(engID, dir, func(ref FindingRef, st *db.State, _ string) ([]chat.Message, error) {
		m := ref.F.Meta
		if !workflow.CanAssign(u, m) {
			return nil, &workflow.Denied{Reason: "only the author or a director can assign reviewers while the finding is open"}
		}
		var list []string
		for _, n := range names {
			if n = strings.TrimSpace(n); n != "" && n != m.Author && !slices.Contains(list, n) {
				list = append(list, n)
			}
		}
		sort.Strings(list)
		var next []db.Reviewer
		for _, n := range list {
			r := db.Reviewer{Name: n}
			for _, old := range st.Reviewers {
				if old.Name == n {
					r.ClearedHash = old.ClearedHash
				}
			}
			next = append(next, r)
		}
		st.Reviewers = next
		return nil, nil
	})
}

func sortedPairs(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "\x00" + m[k] + "\x00")
	}
	return b.String()
}

// CVSSHash identifies the CVSS state (vector + reasons) for optimistic concurrency.
func CVSSHash(m finding.Meta) string {
	return BodyHash(m.CVSS + "\x00" + sortedPairs(m.CVSSReasons))
}

// DetailsHash identifies the details table state for optimistic concurrency.
func DetailsHash(m finding.Meta) string { return BodyHash(sortedPairs(m.Details)) }

// UpdateCVSS sets the CVSS vector (canonicalised) and derived severity, and
// merges reasons (empty value deletes, absent keys are kept). An empty
// vector clears CVSS and keeps the last severity as a manual value.
func (s *Store) UpdateCVSS(engID, dir, vector string, reasons map[string]string, base string, a Actor) error {
	var v cvss.Vector
	if strings.TrimSpace(vector) != "" {
		var err error
		if v, err = cvss.Parse(vector); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidValue, err)
		}
	}
	return s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		m := f.Meta
		if base != "" && CVSSHash(m) != base {
			return "", ErrConflict
		}
		if v == nil {
			if m.CVSS == "" {
				return "clear CVSS", nil
			}
			if err := f.SetMeta("severity", cvss.Derive(m.CVSS, m.Severity)); err != nil {
				return "", err
			}
			return "clear CVSS", f.SetMeta("cvss", nil)
		}
		score, _ := cvss.Score(v)
		merged := map[string]string{}
		for k, r := range m.CVSSReasons {
			merged[k] = r
		}
		for k, r := range reasons {
			if r = strings.TrimSpace(r); r == "" {
				delete(merged, k)
			} else {
				merged[k] = r
			}
		}
		if err := f.SetMeta("severity", cvss.Rating(score)); err != nil {
			return "", err
		}
		if err := f.SetMeta("cvss", v.String()); err != nil {
			return "", err
		}
		var rv any
		if len(merged) > 0 {
			keys := make([]string, 0, len(cvss.Metrics))
			for _, mt := range cvss.Metrics {
				keys = append(keys, mt.Key)
			}
			rv = finding.OrderedMap(keys, merged)
		}
		if err := f.SetMeta("cvss_reasons", rv); err != nil {
			return "", err
		}
		return "set CVSS " + cvss.FormatScore(score), nil
	})
}

// SeverityHash identifies the stored severity for optimistic concurrency.
func SeverityHash(m finding.Meta) string { return BodyHash(m.Severity) }

// UpdateSeverity sets a manual severity; refused when a valid vector exists.
// A non-empty base must match SeverityHash of the current meta.
func (s *Store) UpdateSeverity(engID, dir, sev, base string, a Actor) error {
	if !slices.Contains(s.cfg.Severities, sev) {
		return fmt.Errorf("%w: unknown severity %q", ErrInvalidValue, sev)
	}
	return s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		if base != "" && SeverityHash(f.Meta) != base {
			return "", ErrConflict
		}
		if _, err := cvss.Parse(f.Meta.CVSS); err == nil {
			return "", fmt.Errorf("%w: severity is derived from the CVSS vector", ErrInvalidValue)
		}
		return "set severity " + sev, f.SetMeta("severity", sev)
	})
}

// UpdateDetails replaces the given details rows (other existing rows kept).
func (s *Store) UpdateDetails(engID, dir string, values map[string]string, base string, a Actor) error {
	return s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		if base != "" && DetailsHash(f.Meta) != base {
			return "", ErrConflict
		}
		merged := map[string]string{}
		for k, v := range f.Meta.Details {
			merged[k] = v
		}
		for k, v := range values {
			lines := strings.Split(strings.ReplaceAll(v, "\r\n", "\n"), "\n")
			for i := range lines {
				lines[i] = strings.TrimRight(lines[i], " \t")
			}
			merged[k] = strings.Trim(strings.Join(lines, "\n"), "\n")
		}
		return "edit details", f.SetMeta("details", finding.OrderedMap(s.cfg.DetailsRows, merged))
	})
}
