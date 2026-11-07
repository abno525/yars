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
	"time"

	"yars/internal/chat"
	"yars/internal/cvss"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/store"
	"yars/internal/workflow"
)

// Row is one finding in the table. Severity is derived from a valid CVSS
// vector when present; Score is the formatted base score or "".
type Row struct {
	EngID, Dir, ID, Title, Status, Severity, Author string
	Shown                                           string // Status as the UI shows it (workflow.Shown)
	Score                                           string
	OpenThreads                                     int
	IsRetest                                        bool   // copied into a retest engagement
	RetestResult                                    string // fixed | not_fixed | partially_fixed | ""
	Reviewers                                       []string
	Since                                           time.Time // last workflow event (zero = none)
	Updated                                         time.Time // last chat line of any kind (zero = none)
	Modified                                        time.Time // finding.md last changed on disk (zero = unknown)
	Hash                                            string    // store.ContentHash of finding.md
	// Threads are the open threads, oldest first, each with its last
	// message; Events the workflow events in order (the inbox reads both).
	// Shared between copies of the row: read only.
	Threads []Thread
	Events  []Event
	// Meta is the full front matter with workflow state, for workflow
	// classification. Shared between copies of the row: read only.
	Meta  *finding.Meta
	score float64 // -1 when no valid vector
	// trigrams of the title and of the assets (possible duplicates)
	tgrams, agrams Grams
}

func scoreOf(vec string) (string, float64) {
	v, err := cvss.Parse(vec)
	if err != nil {
		return "", -1
	}
	s, _ := cvss.Score(v)
	return cvss.FormatScore(s), s
}

// Thread is an open chat thread: who started it, where, and its last
// message (the root when it has no reply).
type Thread struct {
	ID, Section, Kind, Starter string
	LastUser, LastText         string
	LastTS                     time.Time
}

// Event is one workflow event of the chat: the action and who did it.
type Event struct {
	Action, User string
	TS           time.Time
}

func rowOf(engID string, ref store.FindingRef, msgs []chat.Message) Row {
	m := ref.F.Meta
	txt, sc := scoreOf(m.CVSS)
	r := Row{EngID: engID, Dir: ref.Dir, ID: m.ID, Title: m.Title, Status: m.Status, Shown: workflow.Shown(m),
		Severity: cvss.Derive(m.CVSS, m.Severity), Author: m.Author, Reviewers: m.Reviewers, Hash: ref.Hash, Modified: ref.Modified,
		Score: txt, score: sc, Meta: &m, tgrams: Trigrams(m.Title), agrams: assetGrams(m.Assets)}
	if m.Retest != nil {
		r.IsRetest, r.RetestResult = true, m.Retest.Result
	}
	for _, msg := range msgs {
		if msg.Event != "" {
			r.Events = append(r.Events, Event{Action: msg.Event, User: msg.User, TS: msg.TS})
			if msg.TS.After(r.Since) {
				r.Since = msg.TS
			}
		}
	}
	chatFields(&r, msgs)
	return r
}

// chatFields sets what a row takes from the chat besides its events: the
// open threads and the time of the last line.
func chatFields(r *Row, msgs []chat.Message) {
	r.OpenThreads, r.Threads, r.Updated = 0, nil, time.Time{}
	for _, msg := range msgs {
		if msg.TS.After(r.Updated) {
			r.Updated = msg.TS
		}
	}
	for _, it := range chat.Timeline(msgs) {
		t := it.Thread
		if t == nil || t.Resolved {
			continue
		}
		last := t.Root
		if n := len(t.Replies); n > 0 {
			last = t.Replies[n-1]
		}
		r.OpenThreads++
		r.Threads = append(r.Threads, Thread{ID: t.Root.ID, Section: t.Root.Section, Kind: t.Root.Kind, Starter: t.Root.User,
			LastUser: last.User, LastText: last.Text, LastTS: last.TS})
	}
}

// Query filters by exact field values (empty = any; an empty Status and
// Shown leave out withdrawn findings) and sorts by
// id|title|status|severity|author (default id). Status matches the stored
// status, Shown the state the UI shows (signed off apart from verification).
type Query struct {
	EngID, Status, Shown, Severity, Author string
	Sort                                   string
	Desc                                   bool
	// Visible limits the rows to these engagements (a user's teams); nil
	// means every engagement.
	Visible map[string]bool
	// Keep are finding folders that pass the status filter whatever their
	// status (rows a bulk change just moved); the other filters still apply.
	Keep map[string]bool
}

// StatusOrder is the workflow order, withdrawn last.
var StatusOrder = workflow.AllStatuses

// ShownOrder is the order of the shown states: signed off between
// verification and complete, withdrawn last.
var ShownOrder = workflow.ShownAll

// Count is one bar segment: how many findings have Key, and their share of
// the engagement's non-withdrawn findings in percent.
type Count struct {
	Key    string
	N, Pct int
}

// Summary is an engagement's findings counted for the board. Withdrawn
// findings count only in Withdrawn and ByStatus["withdrawn"].
type Summary struct {
	Total      int            // findings that are not withdrawn
	Withdrawn  int            // withdrawn findings
	Done       int            // complete + reported
	Progress   int            // Done / Total in percent (0 when empty)
	ByStatus   map[string]int // every stored status, withdrawn included
	ByShown    map[string]int // every shown state (signed off apart), withdrawn included
	BySeverity map[string]int // non-withdrawn only; "" = no severity
	Statuses   []Count        // shown states in ShownOrder, withdrawn last (Pct of Total; 0 for withdrawn)
	Severities []Count        // the configured severities in order
}

func pct(n, of int) int {
	if of == 0 {
		return 0
	}
	return n * 100 / of
}

func summarize(rows []Row, sevs []string) Summary {
	s := Summary{ByStatus: map[string]int{}, ByShown: map[string]int{}, BySeverity: map[string]int{}}
	for _, r := range rows {
		s.ByStatus[r.Status]++
		s.ByShown[r.Shown]++
		if !workflow.Active(r.Status) {
			s.Withdrawn++
			continue
		}
		s.Total++
		s.BySeverity[r.Severity]++
		if r.Status == "complete" || r.Status == "reported" {
			s.Done++
		}
	}
	s.Progress = pct(s.Done, s.Total)
	for _, st := range ShownOrder {
		c := Count{Key: st, N: s.ByShown[st]}
		if workflow.Active(st) {
			c.Pct = pct(c.N, s.Total)
		}
		s.Statuses = append(s.Statuses, c)
	}
	for _, sv := range sevs {
		s.Severities = append(s.Severities, Count{Key: sv, N: s.BySeverity[sv], Pct: pct(s.BySeverity[sv], s.Total)})
	}
	return s
}

// Summary counts an engagement's findings by status and severity, once per
// table generation. The maps are shared: read only.
func (ix *Index) Summary(eng string) (Summary, error) {
	if err := ix.refresh(); err != nil {
		return Summary{}, err
	}
	ix.mu.RLock()
	gen, e := ix.gen, ix.engs[eng]
	ix.mu.RUnlock()
	ix.sumMu.Lock()
	defer ix.sumMu.Unlock()
	if ix.sumGen != gen || ix.sums == nil {
		ix.sumGen, ix.sums = gen, map[string]Summary{}
	}
	if s, ok := ix.sums[eng]; ok {
		return s, nil
	}
	var rows []Row
	if e != nil {
		rows = e.rows
	}
	ix.summaryBuilds.Add(1)
	s := summarize(rows, ix.store.Config().Severities)
	ix.sums[eng] = s
	return s, nil
}

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

	rebuilds  atomic.Int64 // engagement reloads (for tests)
	buildTime atomic.Int64 // nanoseconds the last full build took

	sumMu         sync.Mutex
	sumGen        uint64
	sums          map[string]Summary // per engagement, for sumGen
	summaryBuilds atomic.Int64       // summaries computed (for tests)
	use           map[string]int     // template use, for useGen (under sumMu)
	useGen        uint64
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
	start := time.Now()
	ix.mu.RLock()
	full := len(ix.engs) == 0
	ix.mu.RUnlock()
	if full {
		defer func() { ix.buildTime.Store(int64(max(time.Since(start), time.Nanosecond))) }()
	}
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
		// only the open threads and the last line can have changed
		d := ix.store.DB()
		if d == nil {
			return
		}
		msgs, err := d.Messages(c.Eng, c.Fid)
		if err != nil {
			return
		}
		chatFields(&row, msgs)
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

// Rebuild drops every cached engagement and reads them all again (the admin
// "Rebuild index" button); it returns how long that took.
func (ix *Index) Rebuild() (time.Duration, error) {
	ix.mu.Lock()
	ix.engs, ix.built = map[string]*engRows{}, false
	ix.mu.Unlock()
	if err := ix.flight.do(ix.reload); err != nil {
		return 0, err
	}
	return ix.LastBuild(), nil
}

// LastBuild is how long the last full build of the index took (0 before
// the first one).
func (ix *Index) LastBuild() time.Duration { return time.Duration(ix.buildTime.Load()) }

// Findings is the number of findings in the index, withdrawn ones included.
func (ix *Index) Findings() int {
	ix.refresh()
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	n := 0
	for _, e := range ix.engs {
		n += len(e.rows)
	}
	return n
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

// TemplateUse counts the findings made from each template (their
// "template" front-matter key), over every engagement, withdrawn included.
// The map is cached per table generation: read only.
func (ix *Index) TemplateUse() (map[string]int, error) {
	if err := ix.refresh(); err != nil {
		return nil, err
	}
	ix.mu.RLock()
	gen, engs := ix.gen, ix.engs
	ix.mu.RUnlock()
	ix.sumMu.Lock()
	defer ix.sumMu.Unlock()
	if ix.useGen == gen && ix.use != nil {
		return ix.use, nil
	}
	use := map[string]int{}
	for _, e := range engs {
		for _, r := range e.rows {
			if r.Meta == nil {
				continue
			}
			if t, ok := r.Meta.Extra[store.TemplateKey].(string); ok && t != "" {
				use[t]++
			}
		}
	}
	ix.use, ix.useGen = use, gen
	return use, nil
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

// EngagementsFor lists the engagements in visible (nil = all), sorted by id.
func (ix *Index) EngagementsFor(visible map[string]bool) ([]store.Engagement, error) {
	all, err := ix.Engagements()
	if err != nil || visible == nil {
		return all, err
	}
	out := all[:0]
	for _, e := range all {
		if visible[e.ID] {
			out = append(out, e)
		}
	}
	return out, nil
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

// Titles maps every finding ID of an engagement (any status, withdrawn
// too) to its current title.
func (ix *Index) Titles(eng string) (map[string]string, error) {
	if err := ix.refresh(); err != nil {
		return nil, err
	}
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	out := map[string]string{}
	if e := ix.engs[eng]; e != nil {
		for _, r := range e.rows {
			out[r.ID] = r.Title
		}
	}
	return out, nil
}

// CurrentTitles returns a lookup of findings' current titles for lists of
// past events (notifications): the title now, or then when the finding is
// gone. It reads each engagement once.
func (ix *Index) CurrentTitles() func(eng, fid, then string) string {
	byEng := map[string]map[string]string{}
	return func(eng, fid, then string) string {
		ts, ok := byEng[eng]
		if !ok {
			ts, _ = ix.Titles(eng)
			byEng[eng] = ts
		}
		if t, ok := ts[fid]; ok {
			return t
		}
		return then
	}
}

func (ix *Index) Rows(q Query) ([]Row, error) {
	if err := ix.refresh(); err != nil {
		return nil, err
	}
	// no status filter means every finding that is not withdrawn
	match := func(r Row) bool {
		status := r.Status == q.Status || (q.Status == "" && (q.Shown != "" || workflow.Active(r.Status)))
		status = status && (q.Shown == "" || r.Shown == q.Shown)
		return (status || q.Keep[r.Dir]) && (q.Severity == "" || r.Severity == q.Severity) &&
			(q.Author == "" || r.Author == q.Author)
	}
	var out []Row
	ix.mu.RLock()
	ids := ix.order
	if q.EngID != "" {
		ids = []string{q.EngID}
	}
	for _, id := range ids {
		if q.Visible != nil && !q.Visible[id] {
			continue
		}
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
			return rank(ShownOrder, a.Shown) - rank(ShownOrder, b.Shown)
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
