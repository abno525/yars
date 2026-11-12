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
	"strings"
	"sync"
	"time"

	"yars/internal/chat"
	"yars/internal/config"
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
