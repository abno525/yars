// Package store maps the data repo layout to engagements and findings.
// Every write is a single git commit. All file access goes through an
// os.Root so symlinks cannot reach outside the repository.
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

func New(r *gitrepo.Repo, cfg config.Config) *Store {
	root, err := os.OpenRoot(r.Dir)
	return &Store{repo: r, cfg: cfg, root: root, rootErr: err}
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
// is never modified. One commit; only directors/admins.
//
// assignee becomes the author of every copy (the retester); "" keeps each
// finding's original author.
func (s *Store) CreateRetest(e Engagement, source string, dirs []string, assignee string, u config.User) error {
	dirs = slices.Compact(slices.Sorted(slices.Values(dirs)))
	if u.Role != "director" && u.Role != "admin" {
		return &workflow.Denied{Reason: "only a director or admin can start a retest"}
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
		var errs []error
		set := func(k string, v any) { errs = append(errs, f.SetMeta(k, v)) }
		set("status", "draft")
		if assignee != "" {
			set("author", assignee)
		}
		set("reviewers", []string{})
		set("cleared_by", nil)
		set("returned", nil)
		set("retest", finding.Retest{Source: source + "/" + d, Result: ""})
		if err := errors.Join(errs...); err != nil {
			return err
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
	return s.commit(prev, msg, u.GitAuthor(), dir)
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

// SetRetestResult records the outcome of a retested finding.
func (s *Store) SetRetestResult(engID, dir, result string, a Actor) error {
	if !slices.Contains(workflow.RetestResults, result) {
		return fmt.Errorf("%w: retest result must be fixed, not_fixed or partially_fixed", ErrInvalidValue)
	}
	return s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		if f.Meta.Retest == nil {
			return "", fmt.Errorf("%w: %s is not a retest finding", ErrInvalidValue, f.Meta.ID)
		}
		return "retest result " + result, f.SetMeta("retest", finding.Retest{Source: f.Meta.Retest.Source, Result: result})
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
	var out []FindingRef
	for _, e := range ents {
		if !e.IsDir() || !ValidID(e.Name()) {
			continue
		}
		ref, err := s.Finding(engID, e.Name())
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

func (s *Store) Finding(engID, dir string) (FindingRef, error) {
	if !ValidID(engID) || !ValidID(dir) {
		return FindingRef{}, ErrNotFound
	}
	b, err := s.readFile(findingPath(engID, dir))
	if errors.Is(err, fs.ErrNotExist) {
		return FindingRef{}, ErrNotFound
	}
	if err != nil {
		return FindingRef{}, err
	}
	f, err := finding.Parse(b)
	if err != nil {
		return FindingRef{}, fmt.Errorf("%s/%s: %w", engID, dir, err)
	}
	return FindingRef{EngID: engID, Dir: dir, F: f}, nil
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
	return s.mutateWith(engID, dir, a, func(f *finding.Finding) (string, []chat.Message, error) {
		msg, err := fn(f)
		return msg, nil, err
	})
}

// mutateWith is mutate where fn may also return chat messages to append in
// the same commit (workflow events).
func (s *Store) mutateWith(engID, dir string, a gitrepo.Author, fn func(f *finding.Finding) (string, []chat.Message, error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	head0, _ := s.repo.Head()
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return err
	}
	before := ref.F.Bytes()
	msg, add, err := fn(ref.F)
	if err != nil {
		return err
	}
	after := ref.F.Bytes()
	if string(before) == string(after) && len(add) == 0 {
		return nil
	}
	if err := s.unmoved(head0); err != nil {
		return err
	}
	prev := map[string][]byte{}
	if string(before) != string(after) {
		rel := findingPath(engID, dir)
		orig, err := s.readFile(rel)
		if err != nil {
			return err
		}
		prev[rel] = orig
		if err := s.writeFile(rel, after); err != nil {
			return err
		}
	}
	if err := s.appendChat(engID, dir, add, prev); err != nil {
		s.restore(prev)
		return err
	}
	return s.commit(prev, ref.F.Meta.ID+": "+msg, a, "")
}

func chatPath(eng, dir string) string {
	return path.Join("engagements", eng, "findings", dir, "chat.jsonl")
}

const gitattributesLine = "chat.jsonl merge=union\n"

// appendChat appends messages to the finding's chat.jsonl (and makes sure
// .gitattributes declares the union merge), recording previous contents in
// prev for commit/rollback. Caller holds s.mu.
func (s *Store) appendChat(engID, dir string, msgs []chat.Message, prev map[string][]byte) error {
	if len(msgs) == 0 {
		return nil
	}
	var lines []byte
	for _, m := range msgs {
		l, err := chat.Line(m)
		if err != nil {
			return err
		}
		lines = append(lines, l...)
	}
	cp := chatPath(engID, dir)
	old, err := s.readFile(cp)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	prev[cp] = old // nil when the file did not exist
	if len(old) > 0 && old[len(old)-1] != '\n' {
		old = append(old, '\n')
	}
	if err := s.writeFile(cp, append(slices.Clone(old), lines...)); err != nil {
		return err
	}
	ga, err := s.readFile(".gitattributes")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if !strings.Contains(string(ga), strings.TrimSpace(gitattributesLine)) {
		prev[".gitattributes"] = ga
		next := string(ga)
		if next != "" && !strings.HasSuffix(next, "\n") {
			next += "\n"
		}
		if err := s.writeFile(".gitattributes", []byte(next+gitattributesLine)); err != nil {
			return err
		}
	}
	return nil
}

// restore puts back the previous contents recorded in prev (nil = remove).
func (s *Store) restore(prev map[string][]byte) {
	for p, b := range prev {
		if b == nil {
			s.root.Remove(p)
		} else {
			s.writeFile(p, b)
		}
	}
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

// Chat returns the finding's chat messages (empty when none).
func (s *Store) Chat(engID, dir string) ([]chat.Message, error) {
	if !ValidID(engID) || !ValidID(dir) {
		return nil, ErrNotFound
	}
	b, err := s.readFile(chatPath(engID, dir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return chat.Parse(b), nil
}

// ErrInvalidChat wraps rejected chat input.
var ErrInvalidChat = errors.New("invalid chat message")

// PostChat validates and appends a message as u (one commit). ID, time and
// user are filled in; the returned message is what was stored.
func (s *Store) PostChat(engID, dir string, m chat.Message, u config.User) (chat.Message, error) {
	m.ID, m.TS, m.User, m.Event = chat.NewID(), time.Now().UTC().Truncate(time.Second), u.Username, ""
	m.Text = strings.TrimSpace(m.Text)
	if m.Resolves != "" || m.Reopens != "" {
		m.Text, m.Section = "", "" // markers carry no content
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	head0, _ := s.repo.Head()
	ref, err := s.Finding(engID, dir)
	if err != nil {
		return m, err
	}
	if m.Section != "" {
		if _, ok := ref.F.Section(m.Section); !ok && !slices.Contains(s.cfg.Sections, m.Section) {
			return m, fmt.Errorf("%w: unknown section %q", ErrInvalidChat, m.Section)
		}
	}
	existing, err := s.Chat(engID, dir)
	if err != nil {
		return m, err
	}
	if err := chat.Validate(existing, m); err != nil {
		return m, fmt.Errorf("%w: %v", ErrInvalidChat, err)
	}
	kind := "comment"
	switch {
	case m.Reply != "":
		kind = "reply"
	case m.Resolves != "":
		kind = "resolve thread"
	case m.Reopens != "":
		kind = "reopen thread"
	}
	if err := s.unmoved(head0); err != nil {
		return m, err
	}
	prev := map[string][]byte{}
	if err := s.appendChat(engID, dir, []chat.Message{m}, prev); err != nil {
		s.restore(prev)
		return m, err
	}
	return m, s.commit(prev, ref.F.Meta.ID+": "+kind, u.GitAuthor(), "")
}

// mutateContent is mutate for content edits: a change made while the finding
// is in verification drops existing clearances in the same commit, so the
// director never approves text no reviewer has seen.
func (s *Store) mutateContent(engID, dir string, who Actor, fn func(f *finding.Finding) (string, error)) error {
	return s.mutate(engID, dir, who.GitAuthor(), func(f *finding.Finding) (string, error) {
		if u, ok := who.(config.User); ok && !workflow.CanEdit(u, f.Meta) {
			return "", &workflow.Denied{Reason: "this finding is " + f.Meta.Status + "; only a director can edit it"}
		}
		before := string(f.Bytes())
		msg, err := fn(f)
		if err != nil {
			return "", err
		}
		if f.Meta.Status == "verification" && len(f.Meta.ClearedBy) > 0 && string(f.Bytes()) != before {
			return msg, f.SetMeta("cleared_by", nil)
		}
		return msg, nil
	})
}

// AuthorOf maps an account to its git identity.
func AuthorOf(u config.User) gitrepo.Author { return u.GitAuthor() }

// Actor performs a content edit. A config.User is permission-checked against
// the freshly loaded finding (workflow.CanEdit) inside the store lock; a bare
// gitrepo.Author is a trusted internal caller (tools, tests) and is not.
type Actor interface{ GitAuthor() gitrepo.Author }

// Transition applies a workflow action as u (one commit). Permission and
// gate failures are *workflow.Denied.
func (s *Store) Transition(engID, dir string, act workflow.Action, reason string, u config.User) error {
	apply := func(f *finding.Finding) (string, error) {
		m := f.Meta
		if err := workflow.CheckWithGate(u, m, act, s.cfg); err != nil {
			return "", err
		}
		var errs []error
		set := func(k string, v any) { errs = append(errs, f.SetMeta(k, v)) }
		var msg string
		switch act {
		case workflow.Submit:
			set("cleared_by", nil)
			set("returned", nil)
			msg = "submit for verification"
		case workflow.Return:
			r := strings.TrimSpace(reason)
			if r == "" {
				return "", &workflow.Denied{Reason: "a reason is required to return a finding"}
			}
			set("returned", finding.Returned{By: u.Username, Reason: r})
			set("cleared_by", nil)
			msg = "return to draft\n\n" + r
		case workflow.Clear:
			if !slices.Contains(m.Reviewers, u.Username) {
				// a director reviewing unassigned joins the reviewers
				set("reviewers", append(slices.Clone(m.Reviewers), u.Username))
			}
			set("cleared_by", append(slices.Clone(m.ClearedBy), u.Username))
			msg = "cleared by " + u.Username
		case workflow.Approve:
			msg = "approve"
		case workflow.Reopen:
			set("cleared_by", nil)
			msg = "reopen"
		case workflow.Report:
			msg = "mark reported"
		}
		if _, to := workflow.Target(act); to != m.Status {
			set("status", to)
		}
		return msg, errors.Join(errs...)
	}
	// Style rules (scripts, AI) can be slow, so they run outside the lock on
	// a snapshot; the commit is refused if the finding changed meanwhile.
	linted := ""
	if workflow.Gated(act) && s.Linter != nil {
		ref, err := s.Finding(engID, dir)
		if err != nil {
			return err
		}
		if err := workflow.CheckWithGate(u, ref.F.Meta, act, s.cfg); err != nil {
			return err
		}
		if errs := rules.Errors(s.Linter.Lint(context.Background(), ref.F, rules.All)); len(errs) > 0 {
			return &workflow.Denied{Reason: "cannot " + strings.ToLower(workflow.Label(act)) + ": " + strings.Join(errs, "; ")}
		}
		linted = string(ref.F.Bytes())
	}
	return s.mutateWith(engID, dir, AuthorOf(u), func(f *finding.Finding) (string, []chat.Message, error) {
		if linted != "" && string(f.Bytes()) != linted {
			return "", nil, &workflow.Denied{Reason: "the finding changed while its checks ran; try again"}
		}
		msg, err := apply(f)
		if err != nil {
			return "", nil, err
		}
		ev := chat.Message{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second), User: u.Username, Event: string(act)}
		if act == workflow.Return {
			ev.Text = strings.TrimSpace(reason)
		}
		return msg, []chat.Message{ev}, nil
	})
}

// SetReviewers replaces the reviewer list as u. The author is never a
// reviewer; clearances of removed reviewers are dropped.
func (s *Store) SetReviewers(engID, dir string, names []string, u config.User) error {
	return s.mutate(engID, dir, AuthorOf(u), func(f *finding.Finding) (string, error) {
		m := f.Meta
		if !workflow.CanAssign(u, m) {
			return "", &workflow.Denied{Reason: "only the author or a director can assign reviewers while the finding is open"}
		}
		var list []string
		for _, n := range names {
			if n = strings.TrimSpace(n); n != "" && n != m.Author && !slices.Contains(list, n) {
				list = append(list, n)
			}
		}
		sort.Strings(list)
		var cleared []string
		for _, c := range m.ClearedBy {
			if slices.Contains(list, c) {
				cleared = append(cleared, c)
			}
		}
		var cv any
		if len(cleared) > 0 {
			cv = cleared
		}
		if list == nil {
			list = []string{}
		}
		if err := errors.Join(f.SetMeta("reviewers", list), f.SetMeta("cleared_by", cv)); err != nil {
			return "", err
		}
		if len(list) == 0 {
			return "set reviewers (none)", nil
		}
		return "set reviewers " + strings.Join(list, ", "), nil
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
