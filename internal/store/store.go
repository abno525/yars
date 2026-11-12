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
	"strings"
	"sync"
	"time"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/rules"
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

// AuthorOf maps an account to its git identity.
func AuthorOf(u config.User) gitrepo.Author { return u.GitAuthor() }

// Actor performs a content edit. A config.User is permission-checked against
// the freshly loaded finding (workflow.CanEdit) inside the store lock; a bare
// gitrepo.Author is a trusted internal caller (tools, tests) and is not.
type Actor interface{ GitAuthor() gitrepo.Author }
