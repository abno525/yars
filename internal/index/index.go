// Package index keeps an in-memory table of all findings. Rows are kept per
// engagement, each set tagged with the engagement repo's HEAD and the
// engagement's database change counter; only engagements whose tag moved
// are reloaded. A chat post or workflow change made through the store
// updates just that finding's row.
package index

import (
	"cmp"
	"errors"
	"log"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"yars/internal/chat"
	"yars/internal/cvss"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

// Row is one finding in the table. Severity is derived from a valid CVSS
// vector when present; Score is the formatted base score or "".
type Row struct {
	EngID, Dir, ID, Title, Status, Severity, Author string
	Score                                           string
	OpenThreads                                     int
	IsRetest                                        bool   // copied into a retest engagement
	RetestResult                                    string // fixed | not_fixed | partially_fixed | ""
	Reviewers                                       []string
	// Meta is the full front matter with workflow state, for workflow
	// classification. Shared between copies of the row: read only.
	Meta  *finding.Meta
	score float64 // -1 when no valid vector
}

func scoreOf(vec string) (string, float64) {
	v, err := cvss.Parse(vec)
	if err != nil {
		return "", -1
	}
	s, _ := cvss.Score(v)
	return cvss.FormatScore(s), s
}

func rowOf(engID string, ref store.FindingRef, msgs []chat.Message) Row {
	m := ref.F.Meta
	txt, sc := scoreOf(m.CVSS)
	open, _ := chat.OpenCount(msgs)
	r := Row{EngID: engID, Dir: ref.Dir, ID: m.ID, Title: m.Title, Status: m.Status,
		Severity: cvss.Derive(m.CVSS, m.Severity), Author: m.Author, Reviewers: m.Reviewers,
		Score: txt, score: sc, Meta: &m, OpenThreads: open}
	if m.Retest != nil {
		r.IsRetest, r.RetestResult = true, m.Retest.Result
	}
	return r
}

// Query filters by exact field values (empty = any) and sorts by
// id|title|status|severity|author (default id).
type Query struct {
	EngID, Status, Severity, Author string
	Sort                            string
	Desc                            bool
}

var StatusOrder = []string{"draft", "verification", "complete", "reported"}

// engRows is one engagement's part of the table. It is never changed once
// published; an update replaces it.
type engRows struct {
	eng  store.Engagement
	head string // engagement repo HEAD the rows were read at
	seq  int64  // engagement change counter the rows reflect
	rows []Row  // sorted by Dir
}

type Index struct {
	store *store.Store
	repo  *gitrepo.Repo

	mu    sync.RWMutex
	key   string // store version + database counter last checked
	built bool
	order []string // engagement ids, sorted
	// engs is replaced, never written in place, once published
	engs map[string]*engRows
	list []store.Engagement // engagements in order
	gen  uint64             // moves whenever the table changes

	flight flight
	hintMu sync.Mutex

	rebuilds atomic.Int64 // engagement reloads (for tests)
}

func New(s *store.Store, r *gitrepo.Repo) *Index {
	ix := &Index{store: s, repo: r, engs: map[string]*engRows{}}
	s.OnChange(ix.apply)
	return ix
}

// version identifies the data the index was checked against: every repo's
// HEAD (cached by the store, no git process) plus the database counter.
func (ix *Index) version() (string, error) {
	v, err := ix.store.Version()
	if err != nil {
		return "", err
	}
	if d := ix.store.DB(); d != nil {
		seq, err := d.Seq()
		if err != nil {
			return "", err
		}
		v += "+" + strconv.FormatInt(seq, 10)
	}
	return v, nil
}

func (ix *Index) refresh() error {
	// a caller that joined a reload started before its own check may still
	// be behind: check again (bounded, so constant writes can't starve it)
	for range 3 {
		v, err := ix.version()
		if err != nil {
			return err
		}
		ix.mu.RLock()
		fresh := ix.built && v == ix.key
		ix.mu.RUnlock()
		if fresh {
			return nil
		}
		if err := ix.flight.do(ix.reload); err != nil {
			return err
		}
	}
	return nil
}

// reload brings every engagement whose HEAD or counter moved up to date and
// reuses the others.
func (ix *Index) reload() error {
	key, err := ix.version()
	if err != nil {
		return err
	}
	seqs := map[string]int64{}
	if d := ix.store.DB(); d != nil {
		if seqs, err = d.EngSeqs(); err != nil {
			return err
		}
	}
	ids, err := ix.store.EngagementIDs()
	if err != nil {
		return err
	}
	ix.mu.RLock()
	old := ix.engs
	ix.mu.RUnlock()
	next := make(map[string]*engRows, len(ids))
	var order []string
	changed := len(old) != len(ids)
	for _, id := range ids {
		head, err := ix.store.EngHead(id)
		if err != nil {
			continue
		}
		if e := old[id]; e != nil && e.head == head && e.seq == seqs[id] {
			next[id] = e
			order = append(order, id)
			continue
		}
		e, err := ix.load(id, head, seqs[id])
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				log.Printf("index: skip engagement %s: %v", id, err)
			}
			continue
		}
		next[id], changed = e, true
		order = append(order, id)
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	for id, e := range next {
		// an update applied while we were loading is newer: keep it
		if cur := ix.engs[id]; cur != nil && cur != e && cur.head == e.head && cur.seq > e.seq {
			next[id] = cur
		}
	}
	list := make([]store.Engagement, 0, len(order))
	for _, id := range order {
		list = append(list, next[id].eng)
	}
	ix.engs, ix.order, ix.list, ix.key, ix.built = next, order, list, key, true
	if changed {
		ix.gen++
	}
	return nil
}

// load reads one engagement's findings and chat. head and seq are read
// before the content, so a change landing meanwhile shows as stale later.
func (ix *Index) load(id, head string, seq int64) (*engRows, error) {
	ix.rebuilds.Add(1)
	eng, err := ix.store.Engagement(id)
	if err != nil {
		return nil, err
	}
	refs, err := ix.store.ListFindings(id)
	if err != nil {
		return nil, err
	}
	chats, err := ix.store.EngagementChat(id)
	if err != nil {
		return nil, err
	}
	e := &engRows{eng: eng, head: head, seq: seq, rows: make([]Row, 0, len(refs))}
	for _, r := range refs {
		e.rows = append(e.rows, rowOf(id, r, chats[r.F.Meta.ID]))
	}
	return e, nil
}

// apply updates one finding's row after a database write through the store
// (store.OnChange). It applies only when the engagement's rows reflect
// every earlier change (counter c.Seq-1) and its HEAD hasn't moved;
// otherwise the next refresh reloads the engagement.
func (ix *Index) apply(c store.Change) {
	if c.Kind == store.ChangeContent {
		return // a commit: the engagement's HEAD moved, so it reloads
	}
	ix.hintMu.Lock()
	defer ix.hintMu.Unlock()
	ix.mu.RLock()
	e := ix.engs[c.Eng]
	ix.mu.RUnlock()
	if e == nil || e.seq != c.Seq-1 {
		return
	}
	i := slices.IndexFunc(e.rows, func(r Row) bool { return r.ID == c.Fid })
	if i < 0 {
		return
	}
	if h, err := ix.store.EngHead(c.Eng); err != nil || h != e.head {
		return
	}
	row := e.rows[i]
	if c.Kind == store.ChangeChat {
		// only the open-thread count can have changed
		d := ix.store.DB()
		if d == nil {
			return
		}
		msgs, err := d.Messages(c.Eng, c.Fid)
		if err != nil {
			return
		}
		row.OpenThreads, _ = chat.OpenCount(msgs)
	} else {
		ref, err := ix.store.Finding(c.Eng, row.Dir)
		if err != nil || ref.F.Meta.ID != c.Fid {
			return
		}
		msgs, err := ix.store.ChatOf(ref)
		if err != nil {
			return
		}
		row = rowOf(c.Eng, ref, msgs)
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if ix.engs[c.Eng] != e {
		return // replaced meanwhile; the counters decide what's stale
	}
	rows := slices.Clone(e.rows)
	rows[i] = row
	// the map is published (reload reads it unlocked): replace, don't write
	next := maps.Clone(ix.engs)
	next[c.Eng] = &engRows{eng: e.eng, head: e.head, seq: c.Seq, rows: rows}
	ix.engs = next
	ix.gen++
}

func rank(order []string, v string) int {
	for i, x := range order {
		if strings.EqualFold(x, v) {
			return i
		}
	}
	return len(order)
}

// Gen identifies the current table: it changes whenever any row does, so
// callers can cache what they derive from the rows.
func (ix *Index) Gen() (uint64, error) {
	if err := ix.refresh(); err != nil {
		return 0, err
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return ix.gen, nil
}

// Engagements lists the engagements (sorted by id), cached with the rows.
func (ix *Index) Engagements() ([]store.Engagement, error) {
	if err := ix.refresh(); err != nil {
		return nil, err
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return slices.Clone(ix.list), nil
}

// Engagement looks an engagement up in the cached list.
func (ix *Index) Engagement(id string) (store.Engagement, bool) {
	if err := ix.refresh(); err != nil {
		return store.Engagement{}, false
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	if e := ix.engs[id]; e != nil {
		return e.eng, true
	}
	return store.Engagement{}, false
}

func (ix *Index) Rows(q Query) ([]Row, error) {
	if err := ix.refresh(); err != nil {
		return nil, err
	}
	match := func(r Row) bool {
		return (q.Status == "" || r.Status == q.Status) && (q.Severity == "" || r.Severity == q.Severity) &&
			(q.Author == "" || r.Author == q.Author)
	}
	var out []Row
	ix.mu.RLock()
	ids := ix.order
	if q.EngID != "" {
		ids = []string{q.EngID}
	}
	for _, id := range ids {
		if e := ix.engs[id]; e != nil {
			for _, r := range e.rows {
				if match(r) {
					out = append(out, r)
				}
			}
		}
	}
	ix.mu.RUnlock()

	sev := ix.store.Config().Severities
	less := func(a, b Row) int {
		switch q.Sort {
		case "title":
			return strings.Compare(strings.ToLower(a.Title), strings.ToLower(b.Title))
		case "status":
			return rank(StatusOrder, a.Status) - rank(StatusOrder, b.Status)
		case "severity":
			return rank(sev, a.Severity) - rank(sev, b.Severity)
		case "author":
			return strings.Compare(a.Author, b.Author)
		case "cvss":
			return cmp.Compare(a.score, b.score)
		case "chat":
			return cmp.Compare(a.OpenThreads, b.OpenThreads)
		case "result":
			return strings.Compare(a.RetestResult, b.RetestResult)
		}
		return strings.Compare(a.Dir, b.Dir)
	}
	sort.SliceStable(out, func(i, j int) bool {
		c := less(out[i], out[j])
		if c == 0 {
			c = strings.Compare(out[i].Dir, out[j].Dir)
			return c < 0
		}
		if q.Desc {
			return c > 0
		}
		return c < 0
	})
	return out, nil
}

// flight runs one call at a time; callers arriving while it runs wait for
// it and share its result (a minimal singleflight).
type flight struct {
	mu   sync.Mutex
	call *flightCall
}

type flightCall struct {
	done chan struct{}
	err  error
}

func (f *flight) do(fn func() error) error {
	f.mu.Lock()
	if c := f.call; c != nil {
		f.mu.Unlock()
		<-c.done
		return c.err
	}
	c := &flightCall{done: make(chan struct{})}
	f.call = c
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.call = nil
		f.mu.Unlock()
		close(c.done)
	}()
	c.err = fn()
	return c.err
}
