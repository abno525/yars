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
	"unicode"

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
	ErrConflict    = errors.New("the finding changed since you read it")
	ErrInvalidBody = errors.New("invalid section body")
	// ErrInvalidValue marks a rejected front-matter value (CVSS vector, severity).
	ErrInvalidValue = errors.New("invalid value")
	// ErrNoDB: workflow and chat need the YARS database, which only the server
	// has (a local clone holds content only).
	ErrNoDB = errors.New("workflow state and chat are kept on the YARS server; use its web UI or its /mcp endpoint")
)

type Engagement struct {
	ID     string `yaml:"-" json:"id"`
	Name   string `yaml:"name" json:"name"`
	Client string `yaml:"client" json:"client"`
	Type   string `yaml:"type" json:"type"`
	Source string `yaml:"source,omitempty" json:"source"`
	Start  string `yaml:"start,omitempty" json:"start"`
	End    string `yaml:"end,omitempty" json:"end"`
	// Archived is read from the database: the engagement is read only.
	Archived bool `yaml:"-" json:"archived"`
}

type FindingRef struct {
	EngID, Dir string
	F          *finding.Finding
	// Hash is the ContentHash of finding.md as read ("" for a ref not read
	// from disk); Modified is when the file last changed on disk (zero when
	// unknown).
	Hash     string
	Modified time.Time
}

type Store struct {
	repo    *gitrepo.Repo
	db      *db.DB // nil on a local clone: content only
	root    *os.Root
	rootErr error

	cfgMu   sync.RWMutex
	cfg     config.Config // read through Config()
	cfgSubs []func(config.Config)
	// applyMu orders configurations: each is set and handed to every
	// subscriber before the next (taken before mainMu, never under it)
	applyMu sync.Mutex

	// Git work is serialized per repository: one lock per engagement repo
	// (created on first use) and one for the main repo. Lock order: an
	// engagement's lock before mainMu. Database-only writes (chat,
	// transitions, reviewers) take neither; SQLite serializes them.
	locksMu  sync.Mutex
	engLocks map[string]*sync.Mutex
	mainMu   sync.Mutex

	merging sync.Map // "<eng>/<dir>" of a finding being merged away

	// heads caches each repo's HEAD ("" key = main repo), read from the
	// files under .git (no git process). Our own commits and pushes
	// (Invalidate) drop entries; headGen guards against storing a value
	// read before an invalidation.
	headsMu sync.RWMutex
	heads   map[string]string
	headGen uint64

	reposMu sync.Mutex
	repos   map[string]*gitrepo.Repo // opened engagement repos

	// links caches the main repo's gitlinks (under mainMu), valid while the
	// main HEAD is linksAt.
	links   map[string]string
	linksAt string

	// tplHist caches the templates' versions, valid while the main HEAD is
	// tplHistAt.
	tplHistMu sync.Mutex
	tplHist   map[string][]TemplateVersion
	tplHistAt string

	subsMu sync.RWMutex
	subs   []func(Change)
	evSubs []func(Event) // domain events (see OnEvent)

	// Linter, when set, runs the style rules; error-level violations block
	// submit and approve (unless dismissed).
	Linter Linter

	// checksMu makes starting a check one at a time (held across its
	// database writes, so never taken inside a transaction)
	checksMu sync.Mutex
	// check runs in progress, by "<eng>/<fid>"; runningMu is held only to
	// read or change the map, never across a database call
	runningMu sync.Mutex
	running   map[string]int64
	checkWG   sync.WaitGroup

	beforeWrite func() // test hook: runs between reading and writing
	// beforePurgeGC (test hook) runs in a purge after the rewrite, before
	// the old objects are removed; an error fails the purge there
	beforePurgeGC func() error
	beforeGateMap func() // test hook: the check gate, between reading the latest run and the running map
	beforeClaim   func() // test hook: Make finding, between reading the note and claiming it
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

// Config is the current configuration (Admin › Structure can replace it).
func (s *Store) Config() config.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

// SetConfig replaces the configuration (after config.yaml was saved, on
// the website or by a push) and tells the OnConfig subscribers.
func (s *Store) SetConfig(c config.Config) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.applyConfig(c)
}

// applyConfig sets c and tells the subscribers, under applyMu.
func (s *Store) applyConfig(c config.Config) {
	s.cfgMu.Lock()
	s.cfg = c
	subs := s.cfgSubs
	s.cfgMu.Unlock()
	for _, fn := range subs {
		fn(c)
	}
}

// ReloadConfig applies config.yaml as the main repo has it now and returns
// it: read and applied in one step, so of two saves (a push, Admin ›
// Structure) the one applied last is the one on disk last.
func (s *Store) ReloadConfig() (config.Config, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.mainMu.Lock()
	c, err := config.Load(s.repo.Dir)
	s.mainMu.Unlock()
	if err != nil {
		return config.Config{}, err
	}
	s.applyConfig(c)
	return c, nil
}

// OnConfig registers fn to be told each configuration SetConfig applies
// (the pages and the check rules keep their own copy).
func (s *Store) OnConfig(fn func(config.Config)) {
	s.cfgMu.Lock()
	s.cfgSubs = append(s.cfgSubs, fn)
	s.cfgMu.Unlock()
}

// reloadConfig applies config.yaml as the main repo has it now (after a
// push). One that does not load keeps the running configuration: the push
// checks refuse those, so it is only logged.
func (s *Store) reloadConfig() {
	if _, err := s.ReloadConfig(); err != nil {
		log.Printf("push to the main repo: config.yaml not applied: %v", err)
	}
}
func (s *Store) Repo() *gitrepo.Repo { return s.repo }

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

// writeFile replaces p in one step (a temporary file renamed over it):
// readers that take no lock (chat, workflow changes, pages) never see a
// half-written file.
func (s *Store) writeFile(p string, b []byte) error {
	if s.rootErr != nil {
		return s.rootErr
	}
	tmp := path.Join(path.Dir(p), "."+path.Base(p)+".yars-tmp")
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = s.root.Rename(tmp, p)
	}
	if err != nil {
		s.root.Remove(tmp)
	}
	return err
}

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
		if st.RetestResult == result {
			return nil, nil
		}
		var u string
		if cu, ok := a.(config.User); ok {
			u = cu.Username
		} else {
			u = a.GitAuthor().Name
		}
		st.RetestResult = result
		if st.Status == "verification" {
			// reviewers cleared a different outcome
			for i := range st.Reviewers {
				st.Reviewers[i].ClearedHash = ""
			}
		}
		return []chat.Message{{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second), User: u, Event: "retest", Text: workflow.RetestLabel(result)}}, nil
	})
}

// changeState loads a finding, lets fn change its state, and stores it —
// with any workflow events fn returns — in one database transaction. No git
// commit is made and no git lock is taken: the state is bound to the content
// hash read here, so a concurrent edit makes it stale rather than wrong
// (clearances and approvals count only for the content they were given for).
func (s *Store) changeState(engID, dir string, fn func(ref FindingRef, st *db.State, hash string) ([]chat.Message, error)) error {
	if s.db == nil {
		return ErrNoDB
	}
	ref, raw, err := s.read(engID, dir, nil)
	if err != nil {
		return err
	}
	fid, hash := ref.F.Meta.ID, contentHash(raw)
	// read-modify-write inside one write transaction, so another writer
	// (a request, yars export --mark) can't interleave
	seq, err := s.db.TxForSeq(engID, func(tx *db.Tx) error {
		if err := archivedIn(tx, engID); err != nil {
			return err
		}
		st, err := tx.State(engID, fid)
		if err != nil {
			return err
		}
		applyState(&ref.F.Meta, st, hash)
		msgs, err := fn(ref, &st, hash)
		if err != nil {
			return err
		}
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
	if err != nil {
		return err
	}
	s.notify(Change{Eng: engID, Fid: fid, Kind: ChangeState, Seq: seq})
	return nil
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
	return s.mutateThen(engID, dir, a, fn, nil)
}

// mutateThen is mutate with a step that runs after the commit, still under
// the engagement's lock, with the file's hash before and after.
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
	if string(before) == string(after) {
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
		return ev, then(ref, contentHash(before), contentHash(after))
	}
	return ev, nil
}

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

// mutateContent is mutate for content edits by u, refused once the finding
// is locked. Clearances need no reset: they are bound to the content hash,
// so any change voids them.
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
	return CarryApproval(s.db, ref.EngID, ref.F.Meta.ID, oldHash, newHash)
}

// CarryApproval moves the approval of eng/fid from oldHash to newHash when
// the finding was approved for oldHash (used after a director's edit,
// through YARS or by push).
func CarryApproval(d *db.DB, eng, fid, oldHash, newHash string) error {
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
	return s.TransitionChecked(engID, dir, act, reason, u, nil)
}

// TransitionChecked is Transition with a further rule of the caller (the
// bulk bar's own limits), checked on the finding as it is inside the change.
func (s *Store) TransitionChecked(engID, dir string, act workflow.Action, reason string, u config.User, check func(finding.Meta) error) error {
	if check == nil {
		check = func(finding.Meta) error { return nil }
	}
	if !workflow.NeedsReason(act) {
		reason = "" // only Return, Withdraw and the reverts carry one
	}
	if s.db == nil {
		return ErrNoDB
	}
	if err := s.writable(engID); err != nil {
		return err
	}
	// Style rules (scripts, AI) can be slow, so they run outside the lock on
	// a snapshot; the change is refused if the finding changed meanwhile.
	linted := ""
	if (workflow.Gated(act) || SignsOff(act)) && s.Linter != nil {
		ref, raw, err := s.read(engID, dir, nil)
		if err != nil {
			return err
		}
		if err := workflow.CheckWithGate(u, ref.F.Meta, act, s.Config()); err != nil {
			return err
		}
		if err := check(ref.F.Meta); err != nil {
			return err
		}
		errs, err := s.blocking(act, ref, contentHash(raw), u)
		if err != nil {
			return err
		}
		if len(errs) > 0 {
			return &workflow.Denied{Reason: "cannot " + strings.ToLower(workflow.Label(act)) + ": " + strings.Join(errs, "; ")}
		}
		linted = contentHash(raw)
	}
	var done Event
	err := s.changeState(engID, dir, func(ref FindingRef, st *db.State, hash string) ([]chat.Message, error) {
		done = findingEvent(EventStatus, u.Username, ref)
		done.Action, done.From, done.Reason = string(act), ref.F.Meta.Status, strings.TrimSpace(reason)
		if linted != "" && hash != linted {
			return nil, &workflow.Denied{Reason: "the finding changed while its checks ran; try again"}
		}
		if linted != "" && SignsOff(act) {
			// a run started since the read above: the content it covers now
			if g, err := s.checkGate(engID, ref.F.Meta.ID, hash); err != nil {
				return nil, err
			} else if g != "" {
				return nil, &workflow.Denied{Reason: "cannot " + strings.ToLower(workflow.Label(act)) + ": " + g}
			}
		}
		if err := workflow.CheckWithGate(u, ref.F.Meta, act, s.Config()); err != nil {
			return nil, err
		}
		if err := check(ref.F.Meta); err != nil {
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
		case workflow.Withdraw:
			r := strings.TrimSpace(reason)
			if r == "" {
				return nil, &workflow.Denied{Reason: "a reason is required to withdraw a finding"}
			}
			uncleared()
			st.ApprovedHash = ""
			st.ReturnedBy, st.ReturnedReason = "", ""
			st.WithdrawnBy, st.WithdrawnReason, ev.Text = u.Username, r, r
		case workflow.Revise:
			uncleared()
			st.WithdrawnBy, st.WithdrawnReason = "", ""
			st.ReturnedBy, st.ReturnedReason = "", ""
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
			r := strings.TrimSpace(reason)
			if r == "" {
				return nil, &workflow.Denied{Reason: "a reason is required to revert a finding"}
			}
			uncleared()
			st.ApprovedHash = ""
			ev.Text = r
		case workflow.Unreport:
			// back to complete: the approval, the sign-offs and the remote
			// pages of earlier exports stay (R4)
			r := strings.TrimSpace(reason)
			if r == "" {
				return nil, &workflow.Denied{Reason: "a reason is required to revert a finding"}
			}
			ev.Text = r
		case workflow.TakeBack:
			uncleared() // the author changes it again: sign-offs start over
			st.ReturnedBy, st.ReturnedReason = "", ""
		case workflow.Approve:
			st.ApprovedHash = hash // approval is for exactly this content
		}
		_, st.Status = workflow.Target(act)
		return []chat.Message{ev}, nil
	})
	if err != nil {
		return err
	}
	_, done.To = workflow.Target(act)
	s.Emit(done)
	return nil
}

// MarkExported marks a complete finding reported because u sent it to a
// destination that marks what it gets (mark_reported). It is the
// destination's doing, not u's workflow power, so any sender may; the
// event's text names the destination. Not complete: *workflow.Denied.
func (s *Store) MarkExported(engID, dir, destination string, u config.User) error {
	if s.db == nil {
		return ErrNoDB
	}
	if err := s.writable(engID); err != nil {
		return err
	}
	var done Event
	err := s.changeState(engID, dir, func(ref FindingRef, st *db.State, _ string) ([]chat.Message, error) {
		from, to := workflow.Target(workflow.Report)
		if !slices.Contains(from, ref.F.Meta.Status) {
			return nil, &workflow.Denied{Reason: ref.F.Meta.ID + " is " + ref.F.Meta.Status + ", not complete"}
		}
		done = findingEvent(EventStatus, u.Username, ref)
		done.Action, done.From, done.To, done.Destination = string(workflow.Report), ref.F.Meta.Status, to, destination
		st.Status = to
		return []chat.Message{{ID: chat.NewID(), TS: time.Now().UTC().Truncate(time.Second), User: u.Username,
			Event: string(workflow.Report), Text: destination}}, nil
	})
	if err == nil {
		s.Emit(done)
	}
	return err
}

// SetReviewers replaces the reviewer list as u. The author is never a
// reviewer; clearances of reviewers who stay are kept.
func (s *Store) SetReviewers(engID, dir string, names []string, u config.User) error {
	var done Event
	err := s.changeState(engID, dir, func(ref FindingRef, st *db.State, _ string) ([]chat.Message, error) {
		m := ref.F.Meta
		if !workflow.CanAddReviewers(u, m) {
			return nil, reviewersDenied(m)
		}
		done = findingEvent(EventReviewers, u.Username, ref)
		done.State = m.Status
		var list []string
		for _, n := range names {
			if n = strings.TrimSpace(n); n != "" && n != m.Author && !slices.Contains(list, n) {
				list = append(list, n)
			}
		}
		if !workflow.CanAssign(u, m) {
			// a reviewer only adds: nobody assigned (or signed off) is dropped
			for _, old := range st.Reviewers {
				if !slices.Contains(list, old.Name) {
					return nil, &workflow.Denied{Reason: "only the author or a director can remove a reviewer"}
				}
			}
			isOld := func(n string) bool {
				return slices.ContainsFunc(st.Reviewers, func(r db.Reviewer) bool { return r.Name == n })
			}
			for _, n := range list {
				if !isOld(n) && !workflow.CanAddReviewer(u, m, n) {
					return nil, &workflow.Denied{Reason: errSelfAssign}
				}
			}
		}
		sort.Strings(list)
		var next []db.Reviewer
		done.Reviewers, done.Added = list, nil
		for _, n := range list {
			r := db.Reviewer{Name: n}
			added := true
			for _, old := range st.Reviewers {
				if old.Name == n {
					r.ClearedHash, added = old.ClearedHash, false
				}
			}
			if added {
				done.Added = append(done.Added, n)
			}
			next = append(next, r)
		}
		st.Reviewers = next
		return nil, nil
	})
	if err == nil && len(done.Added) > 0 {
		s.Emit(done)
	}
	return err
}

const errSelfAssign = "only the author or a director can make you a reviewer"

// reviewersDenied is why the reviewer list of m cannot change: the finding
// is no longer open, or the user may not assign.
func reviewersDenied(m finding.Meta) error {
	if m.Status != "draft" && m.Status != "verification" {
		return &workflow.Denied{Reason: "reviewers can only change in draft or verification (finding is " + m.Status + ")"}
	}
	return &workflow.Denied{Reason: "only a reviewer, the author or a director can assign reviewers"}
}

// AddReviewers adds names to the reviewer list as u, merged with the list as
// it is inside the change, so a reviewer someone added meanwhile (and their
// sign-off) stays. The author's name, and u's own when u may only add
// (workflow.CanAddReviewer), are skipped; when no name could be added and
// none was on the list already, it is *workflow.Denied.
func (s *Store) AddReviewers(engID, dir string, names []string, u config.User) error {
	var done Event
	err := s.changeState(engID, dir, func(ref FindingRef, st *db.State, _ string) ([]chat.Message, error) {
		m := ref.F.Meta
		if !workflow.CanAddReviewers(u, m) {
			return nil, reviewersDenied(m)
		}
		done = findingEvent(EventReviewers, u.Username, ref)
		done.State = m.Status
		var refused []string
		kept := false
		for _, n := range names {
			switch n = strings.TrimSpace(n); {
			case n == "":
			case slices.ContainsFunc(st.Reviewers, func(r db.Reviewer) bool { return r.Name == n }):
				kept = true
			case n == m.Author:
				refused = append(refused, n+" wrote this finding")
			case !workflow.CanAddReviewer(u, m, n):
				refused = append(refused, errSelfAssign)
			default:
				st.Reviewers = append(st.Reviewers, db.Reviewer{Name: n})
				done.Added = append(done.Added, n)
			}
		}
		if len(done.Added) == 0 && !kept {
			if len(refused) == 0 {
				refused = []string{"no reviewer given"}
			}
			return nil, &workflow.Denied{Reason: strings.Join(refused, "; ")}
		}
		sort.Slice(st.Reviewers, func(i, j int) bool { return st.Reviewers[i].Name < st.Reviewers[j].Name })
		done.Reviewers = nil
		for _, r := range st.Reviewers {
			done.Reviewers = append(done.Reviewers, r.Name)
		}
		return nil, nil
	})
	if err == nil && len(done.Added) > 0 {
		s.Emit(done)
	}
	return err
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
	_, err := s.UpdateCVSSRows(engID, dir, CVSSChange{Vector: &vector, Reasons: reasons, Table: base}, a)
	return err
}

// CVSSRow is the key of the vector among CVSSChange.Bases (the reasons are
// keyed by metric).
const CVSSRow = "cvss"

// CVSSChange is an edit of the CVSS rows: the vector (nil keeps it, read
// inside the change) and reasons by metric (empty deletes). Each row with a
// base in Bases (RowHash of the value read) is refused only if that row
// changed since; Table, the whole state's base (CVSSHash), passes them all
// while nothing changed.
type CVSSChange struct {
	Vector  *string
	Reasons map[string]string
	Bases   map[string]string
	Table   string
}

// CVSSRowHashes are the bases of the vector (CVSSRow) and of each reason.
// A reason's base covers its metric's value too: the reason explains that
// value, so an edit of it is refused once the metric changed.
func CVSSRowHashes(m finding.Meta) map[string]string {
	out := map[string]string{CVSSRow: RowHash(m.CVSS)}
	for _, mt := range cvss.Metrics {
		out[mt.Key] = RowHash(reasonRow(m, mt.Key))
	}
	return out
}

// reasonRow is what a reason's base is of: its metric's value and the
// reason.
func reasonRow(m finding.Meta, key string) string {
	val := ""
	if v, err := cvss.ParsePartial(m.CVSS); err == nil {
		val = v[key]
	}
	return val + "\x00" + m.CVSSReasons[key]
}

// ReasonHash is the base of a reason with its metric at value (as
// CVSSRowHashes gives it).
func ReasonHash(value, reason string) string {
	return RowHash(value + "\x00" + strings.TrimSpace(reason))
}

// UpdateCVSSRows applies ch (see UpdateCVSS) and returns the new bases of
// every CVSS row.
func (s *Store) UpdateCVSSRows(engID, dir string, ch CVSSChange, a Actor) (map[string]string, error) {
	var v cvss.Vector
	if ch.Vector != nil && strings.TrimSpace(*ch.Vector) != "" {
		var err error
		if v, err = cvss.Parse(*ch.Vector); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidValue, err)
		}
		// stored canonical, in the configured version (as a push must be)
		if _, err := CheckCVSS(s.Config(), v.String()); err != nil {
			return nil, err
		}
	}
	reasons := ch.Reasons
	var out map[string]string
	err := s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		m := f.Meta
		if ch.Table == "" || CVSSHash(m) != ch.Table {
			// exactly the rows written, each against its own base; once
			// any base is given, a written row without one is refused
			checked := ch.Table != "" || len(ch.Bases) > 0
			stale := func(k, cur string) bool {
				b, ok := ch.Bases[k]
				if !ok {
					return checked
				}
				return b != "" && RowHash(cur) != b
			}
			if ch.Vector != nil && stale(CVSSRow, m.CVSS) {
				return "", ErrConflict
			}
			for k := range reasons {
				if stale(k, reasonRow(m, k)) {
					return "", ErrConflict
				}
			}
		}
		if ch.Vector == nil {
			// the vector as it is now (a reason edit never writes back an
			// older one)
			var err error
			if v, err = cvss.Parse(m.CVSS); err != nil {
				return "", fmt.Errorf("%w: set a CVSS vector first", ErrInvalidValue)
			}
		}
		msg, err := writeCVSS(f, m, v, reasons)
		if err == nil {
			nm := m
			nm.CVSS, nm.CVSSReasons = "", mergeReasons(m.CVSSReasons, reasons)
			if v != nil {
				nm.CVSS = v.String()
			} else {
				nm.CVSSReasons = m.CVSSReasons
			}
			out = CVSSRowHashes(nm)
		}
		return msg, err
	})
	return out, err
}

// mergeReasons is old with reasons applied (an empty one deletes).
func mergeReasons(old, reasons map[string]string) map[string]string {
	merged := map[string]string{}
	for k, r := range old {
		merged[k] = r
	}
	for k, r := range reasons {
		if r = strings.TrimSpace(r); r == "" {
			delete(merged, k)
		} else {
			merged[k] = r
		}
	}
	return merged
}

// writeCVSS sets vector v (nil clears it) and merges reasons into f, whose
// meta was m.
func writeCVSS(f *finding.Finding, m finding.Meta, v cvss.Vector, reasons map[string]string) (string, error) {
	{
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
		merged := mergeReasons(m.CVSSReasons, reasons)
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
		if m.CVSS == v.String() {
			// the vector stays: name the reasons that changed
			var changed []string
			for _, mt := range cvss.Metrics {
				if merged[mt.Key] != m.CVSSReasons[mt.Key] {
					changed = append(changed, mt.Key)
				}
			}
			switch len(changed) {
			case 0:
			case 1:
				return "edit CVSS reason " + changed[0], nil
			default:
				return "edit CVSS reasons " + strings.Join(changed, ", "), nil
			}
		}
		return "set CVSS " + cvss.FormatScore(score), nil
	}
}

// SeverityHash identifies the stored severity for optimistic concurrency.
func SeverityHash(m finding.Meta) string { return BodyHash(m.Severity) }

// UpdateSeverity sets a manual severity; refused when a valid vector exists.
// A non-empty base must match SeverityHash of the current meta.
func (s *Store) UpdateSeverity(engID, dir, sev, base string, a Actor) error {
	if sev == "" {
		return fmt.Errorf("%w: choose a severity", ErrInvalidValue)
	}
	if err := CheckSeverity(s.Config(), sev, ""); err != nil {
		return err
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

// RowHash identifies one value (a details row, the CVSS vector, one CVSS
// reason) for optimistic concurrency per row.
func RowHash(value string) string { return BodyHash("\x00row\x00" + value) }

// DetailsRowHashes are the bases of each details row (RowHash).
func DetailsRowHashes(m finding.Meta) map[string]string {
	out := map[string]string{}
	for k, v := range m.Details {
		out[k] = RowHash(v)
	}
	return out
}

// UpdateDetails replaces the given details rows (other existing rows kept).
// A non-empty base is the whole table's (DetailsHash), or for a single row
// that row's own (RowHash).
func (s *Store) UpdateDetails(engID, dir string, values map[string]string, base string, a Actor) error {
	_, err := s.UpdateDetailsBase(engID, dir, values, base, a)
	return err
}

// UpdateDetailsBase is UpdateDetails returning the new base (RowHash) of
// each written row.
func (s *Store) UpdateDetailsBase(engID, dir string, values map[string]string, base string, a Actor) (map[string]string, error) {
	if base == "" {
		return s.UpdateDetailsRows(engID, dir, values, nil, a)
	}
	var out map[string]string
	err := s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		ok := DetailsHash(f.Meta) == base
		if len(values) == 1 {
			for k := range values {
				ok = ok || RowHash(f.Meta.Details[k]) == base
			}
		}
		if !ok {
			return "", ErrConflict
		}
		msg, err := s.writeDetails(f, values)
		out = map[string]string{}
		for k := range values {
			out[k] = RowHash(f.Meta.Details[k])
		}
		return msg, err
	})
	return out, err
}

// UpdateDetailsRows replaces the given details rows, each checked on its
// own: a row with a base (RowHash of the value it was read with) is refused
// with ErrConflict only when that row changed since; with no bases at all
// nothing is checked, but once bases are given a written row without one
// is refused. Other rows are kept. It returns each written row's new base.
func (s *Store) UpdateDetailsRows(engID, dir string, values, bases map[string]string, a Actor) (map[string]string, error) {
	var out map[string]string
	err := s.mutateContent(engID, dir, a, func(f *finding.Finding) (string, error) {
		for k := range values {
			b, ok := bases[k]
			// once any base is given, a written row without one is refused
			if (!ok && len(bases) > 0) || (b != "" && RowHash(f.Meta.Details[k]) != b) {
				return "", ErrConflict
			}
		}
		msg, err := s.writeDetails(f, values)
		out = map[string]string{}
		for k := range values {
			out[k] = RowHash(f.Meta.Details[k])
		}
		return msg, err
	})
	return out, err
}

// CleanRow is a details value as stored: no trailing blanks on a line, no
// blank lines around it.
func CleanRow(v string) string {
	lines := strings.Split(strings.ReplaceAll(v, "\r\n", "\n"), "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t")
	}
	return strings.Trim(strings.Join(lines, "\n"), "\n")
}

func (s *Store) writeDetails(f *finding.Finding, values map[string]string) (string, error) {
	merged := map[string]string{}
	for k, v := range f.Meta.Details {
		merged[k] = v
	}
	for k, v := range values {
		merged[k] = CleanRow(v)
	}
	if err := f.SetMeta("details", finding.OrderedMap(s.Config().DetailsRows, merged)); err != nil {
		return "", err
	}
	f.Meta.Details = merged
	return "edit details", nil
}
