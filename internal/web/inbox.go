package web

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

// The inbox: one layout for every role. Queues come in workflow.QueueOrder;
// a role always sees its own (the workflow's Queues: in the simple one every
// account has the same), another queue only while it holds something of
// the user's (a reviewer's own returned finding). Every
// row has the same columns: title | tag | engagement · ID | who · what |
// time | one action (a link; nothing changes on GET).

// inboxRow is one row of any queue, ready to draw.
type inboxRow struct {
	Key                string // "eng/dir" of a finding (the pick value); "" for a note
	Title, URL         string
	TagClass, Tag      string // severity or note state; "" = an empty slot
	EngID, EngName, ID string
	Who, What          string
	At                 time.Time
	Act, ActURL        string
	Primary            bool
	NoteID             int64     // a notice (Notifications): Open posts to it
	row                index.Row // the finding (bulk menu, refresh after a run)
}

// inboxView is a user's queues. Lists (findings and threads) are built once
// per index generation and shared: read only. Board and Notes are read per
// request.
type inboxView struct {
	Lists      map[workflow.Inbox][]inboxRow
	Board      []inboxRow
	BoardTotal int // notes with something new (Board is capped)
	Notes      []inboxRow
	NotesTotal int // unread notices (Notes is capped)
}

// Count is the nav badge: every row of every queue the user sees.
func (v inboxView) Count() int {
	n := v.BoardTotal + v.NotesTotal
	for _, l := range v.Lists {
		n += len(l)
	}
	return n
}

// inboxCache holds each user's inbox for one index generation; views are
// shared between requests, so they are read only.
type inboxCache struct {
	mu     sync.Mutex
	gen    uint64
	byUser map[string]inboxView
	builds int // classifications done (for tests)
}

var inboxHeadings = map[workflow.Inbox]string{
	workflow.InboxReturned: "Returned to me", workflow.InboxReview: "Awaiting my review", workflow.InboxApprove: "Ready to approve",
	workflow.InboxReport: "Ready to mark reported", workflow.InboxThreads: "Open threads on my findings",
	workflow.InboxBoard: "New on team board", workflow.InboxNotes: "Notifications",
}

// inboxWho heads the who · what column of each queue.
var inboxWho = map[workflow.Inbox]string{
	workflow.InboxReturned: "Returned by", workflow.InboxReview: "Author", workflow.InboxApprove: "Signed off by",
	workflow.InboxReport: "Approved by", workflow.InboxThreads: "Last message", workflow.InboxBoard: "Latest",
	workflow.InboxNotes: "By",
}

// inboxFor classifies every finding across the open engagements u sees,
// once per index generation.
func (s *Server) inboxFor(u config.User, engs []store.Engagement) (inboxView, error) {
	gen, err := s.Index.Gen()
	if err != nil {
		return inboxView{}, err
	}
	// team changes and archiving move the index generation, so the key
	// needs no team set
	key := u.Username + "\x00" + u.Role + "\x00" + strconv.FormatBool(u.IsAdmin)
	c := &s.inboxes
	c.mu.Lock()
	if c.byUser == nil || c.gen != gen {
		c.gen, c.byUser = gen, map[string]inboxView{}
	}
	v, ok := c.byUser[key]
	c.mu.Unlock()
	if ok {
		return v, nil
	}
	// rows are at least as new as gen: a newer change only means the next
	// request classifies again
	vis, err := s.Store.Visible(u)
	if err != nil {
		return inboxView{}, err
	}
	open := map[string]bool{}
	names := map[string]string{}
	for _, e := range engs {
		if (vis == nil || vis[e.ID]) && !e.Archived {
			open[e.ID] = true
			names[e.ID] = e.Name
		}
	}
	rows, err := s.Index.Rows(index.Query{Sort: "severity", Visible: open})
	if err != nil {
		return inboxView{}, err
	}
	v.Lists = map[workflow.Inbox][]inboxRow{}
	f := s.flow()
	// open threads are a pentester's and a reviewer's queue only (in the
	// simple workflow everyone's)
	threads := slices.Contains(f.Queues(u), workflow.InboxThreads)
	// the sections every finding page has a panel for, whatever its file holds
	panels := append(slices.Clone(s.conf().Sections), store.PanelTargets...)
	for _, r := range rows {
		if r.Meta == nil {
			continue
		}
		if k := workflow.Pending(u, *r.Meta); k != workflow.InboxNone {
			v.Lists[k] = append(v.Lists[k], findingRowFor(f, k, u, r, names[r.EngID]))
		}
		if threads {
			v.Lists[workflow.InboxThreads] = append(v.Lists[workflow.InboxThreads], threadRows(u, r, names[r.EngID], panels)...)
		}
	}
	slices.SortStableFunc(v.Lists[workflow.InboxThreads], func(a, b inboxRow) int { return b.At.Compare(a.At) })
	c.mu.Lock()
	c.builds++
	if c.gen == gen {
		c.byUser[key] = v
	}
	c.mu.Unlock()
	return v, nil
}

// baseRow is a finding's part of a row: title, severity, where it is.
func baseRow(r index.Row, engName string) inboxRow {
	ir := inboxRow{Key: r.EngID + "/" + r.Dir, Title: r.Title, URL: findingURL(r.EngID, r.Dir), EngID: r.EngID, EngName: engName,
		ID: r.ID, row: r}
	if r.Severity != "" {
		ir.TagClass, ir.Tag = "sev-"+r.Severity, r.Severity
	}
	ir.ActURL = ir.URL
	return ir
}

// lastEvent is the newest event of action on the row by someone ok accepts.
func lastEvent(r index.Row, action string, ok func(user string) bool) (index.Event, bool) {
	for i := len(r.Events) - 1; i >= 0; i-- {
		if ev := r.Events[i]; ev.Action == action && ok(ev.User) {
			return ev, true
		}
	}
	return index.Event{}, false
}

func anyone(string) bool { return true }

// inboxWhoFor heads queue k's who · what column in workflow f: in the
// simple one Ready to mark reported names who completed a finding.
func inboxWhoFor(f workflow.Flow, k workflow.Inbox) string {
	if f.Simple && k == workflow.InboxReport {
		return "Completed by"
	}
	return inboxWho[k]
}

// findingRow is the row of a finding in queue k for u, in the standard
// workflow.
func findingRow(k workflow.Inbox, u config.User, r index.Row, engName string) inboxRow {
	return findingRowFor(workflow.Flow{}, k, u, r, engName)
}

// findingRowFor is the row of a finding in queue k for u in workflow f.
func findingRowFor(f workflow.Flow, k workflow.Inbox, u config.User, r index.Row, engName string) inboxRow {
	ir := baseRow(r, engName)
	m := r.Meta
	ir.At = r.Since
	switch k {
	case workflow.InboxReturned:
		ir.Act, ir.Primary = "Fix", true
		if m.Returned != nil {
			ir.Who, ir.What = m.Returned.By, excerpt(m.Returned.Reason)
		}
	case workflow.InboxReview:
		ir.Act, ir.Who, ir.What = "Review", r.Author, "submitted"
		// u signed off or returned it before: it came back changed
		if _, ok := lastEvent(r, string(workflow.Clear), func(n string) bool { return n == u.Username }); ok {
			ir.What = "edited after your review"
		} else if _, ok := lastEvent(r, string(workflow.Return), func(n string) bool { return n == u.Username }); ok {
			ir.What = "edited after your review"
		}
	case workflow.InboxApprove:
		ir.Act, ir.Primary, ir.What = "Approve", true, "signed off"
		if ev, ok := lastEvent(r, string(workflow.Clear), func(n string) bool { return n != u.Username && slices.Contains(m.ClearedBy, n) }); ok {
			ir.Who, ir.At = ev.User, ev.TS
		} else {
			// state set without events (a migration, a seed)
			for _, n := range m.ClearedBy {
				if n != u.Username {
					ir.Who = n
				}
			}
		}
	case workflow.InboxReport:
		// who approved it; in the simple workflow who completed it
		by, what := workflow.Approve, "approved"
		if f.Simple {
			by, what = workflow.Complete, "completed"
		}
		ir.Act, ir.Primary, ir.What = "Mark reported", true, what
		if ev, ok := lastEvent(r, string(by), anyone); ok {
			ir.Who, ir.At = ev.User, ev.TS
		} else {
			// approved without an event (a migration, a seed): the
			// approver is not recorded anywhere else; the cell shows the
			// muted dash of an empty value
			ir.What = ""
		}
	}
	// no event to date it: the last chat line, else the last edit
	if ir.At.IsZero() {
		ir.At = r.Updated
	}
	if ir.At.IsZero() {
		ir.At = r.Modified
	}
	return ir
}

// threadRows are u's open threads of a finding u wrote or reviews whose
// last message is someone else's. A check run's thread counts only once a
// person wrote in it (the AI's answer for a user is not that). panels are
// the sections every finding page shows (configured ones and the panels a
// comment can point at): a thread on a section that is neither one of them
// nor in the finding's file leads to the chat, as a general one does.
func threadRows(u config.User, r index.Row, engName string, panels []string) []inboxRow {
	if r.Author != u.Username && !slices.Contains(r.Reviewers, u.Username) {
		return nil
	}
	var out []inboxRow
	for _, t := range r.Threads {
		if t.LastUser == u.Username || t.LastUser == store.CheckUser || t.LastKind == chat.KindAI {
			continue
		}
		ir := baseRow(r, engName)
		ir.Who, ir.What, ir.At, ir.Act = t.LastUser, excerpt(t.LastText), t.LastTS, "Reply"
		// the anchor is a slug of the section name: letters, digits, dashes
		if t.Section != "" && (slices.Contains(r.Sections, t.Section) || slices.Contains(panels, t.Section)) {
			ir.ActURL += "#s-" + anchor(t.Section)
		} else {
			ir.ActURL += "#chat"
		}
		out = append(out, ir)
	}
	return out
}

// openCache remembers which findings have open checks (Store.OpenChecks),
// by "eng/dir", for as long as nothing they depend on changed: the index
// (content), the database (runs, dismissals) and the rule set. Every page a
// director loads filters Ready to approve for the nav badge; the findings
// list's bulk bar reads it too (gatedRows).
type openCache struct {
	mu   sync.Mutex
	key  openKey
	open map[string]bool
	runs int // OpenChecks calls (for tests)
}

type openKey struct {
	gen  uint64
	seq  int64
	set  *rules.Set
	lint string // the linter in use (tests swap it)
}

// valid returns the cached answers (a copy) and the key they are for, after
// dropping them if anything changed since.
func (c *openCache) valid(s *Server) (map[string]bool, openKey, error) {
	var k openKey
	var err error
	// the stamps before the content: a change in between only means the
	// next request reads again
	if d := s.Store.DB(); d != nil {
		if k.seq, err = d.Seq(); err != nil {
			return nil, k, err
		}
	}
	if k.gen, err = s.Index.Gen(); err != nil {
		return nil, k, err
	}
	k.lint = fmt.Sprintf("%p", s.Store.Linter)
	if s.Rules != nil {
		k.set = s.Rules.Rules()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open == nil || c.key != k {
		c.key, c.open = k, map[string]bool{}
	}
	return maps.Clone(c.open), k, nil
}

// put records an answer read for key k (dropped when the key moved on).
func (c *openCache) put(k openKey, finding string, open bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runs++
	if c.key == k {
		c.open[finding] = open
	}
}

// withoutOpenChecks drops from Ready to approve the findings with open
// (undismissed) check errors or warnings (Store.OpenChecks, the gate's own
// source), and with Require Check on those without a finished check run on
// their content (Store.CheckGates): a director gets clean findings only. Read now, since runs,
// dismissals and rule changes do not wait for the index. v is shared: a
// changed view gets its own lists map.
func (s *Server) withoutOpenChecks(v inboxView) (inboxView, error) {
	rows := v.Lists[workflow.InboxApprove]
	if len(rows) == 0 || s.Store.Linter == nil {
		return v, nil
	}
	known, key, err := s.openCache.valid(s)
	if err != nil {
		return v, err
	}
	drop := map[string]bool{}
	// Require Check: the latest run must have finished on the content (read
	// now in one query, never cached: runs start and fail without moving a
	// change counter, and the setting can change)
	keys := make([]store.GateKey, 0, len(rows))
	for _, r := range rows {
		keys = append(keys, store.GateKey{Eng: r.EngID, Fid: r.row.ID, Hash: r.row.Full})
	}
	gates, err := s.Store.CheckGates(keys)
	if err != nil {
		return v, err
	}
	for _, r := range rows {
		if gates[r.EngID+"/"+r.row.ID] != "" {
			drop[r.Key] = true
			continue
		}
		open, ok := known[r.Key]
		if !ok {
			vs, err := s.Store.OpenChecks(r.EngID, r.row.Dir)
			if errors.Is(err, store.ErrNotFound) {
				continue // gone since the index read it: the next one drops it
			}
			if err != nil {
				return v, err
			}
			open = len(vs) > 0
			s.openCache.put(key, r.Key, open)
		}
		if open {
			drop[r.Key] = true
		}
	}
	if len(drop) == 0 {
		return v, nil
	}
	lists := maps.Clone(v.Lists)
	lists[workflow.InboxApprove] = slices.DeleteFunc(slices.Clone(rows), func(r inboxRow) bool { return drop[r.Key] })
	v.Lists = lists
	return v, nil
}

// inboxList is one page of a queue; "Load more" appends the next.
type inboxList struct {
	Name     workflow.Inbox
	Heading  string
	TagHead  string // the tag column: Severity, or State for notes
	WhoHead  string
	Total    int // rows in the whole queue
	Rows     []inboxRow
	Offset   int
	PageSize int
	MoreURL  string // the next page ("" = no more)
	// Bulk is the director's bar the queue's picks belong to (queues 3 and
	// 4); nil = no pick column
	Bulk *bulkBar
}

// Cols is how many columns the queue's table has.
func (l inboxList) Cols() int {
	if l.Bulk != nil {
		return 7
	}
	return 6
}

// inboxLists are the inbox page's queues, one page each, in order.
type inboxLists struct {
	Queues []inboxList
	Bulk   *bulkBar // the director's bar ("" = none)
	// Stale: the findings of the viewer's review and approve queues whose
	// check is out of date only because the rules changed (Check stale)
	Stale int
}

// maxCheckStale is how many checks one press of Check stale starts: the
// queue holds each waiting finding in memory, and a check may ask the AI
// provider. The count on the page says what is left.
const maxCheckStale = 100

// staleRows are the findings of u's Awaiting my review and Ready to approve
// queues (before the approve queue is filtered: a finding that waits for a
// check is not listed there) whose latest check is out of date for one
// reason alone: the rules changed since (store.GateRules). A finding never
// checked, one whose text changed and one being checked are not among them.
// With Require Check off there are none.
//
// The simple workflow has neither queue, and the check gates Complete
// there: its findings are the drafts u wrote, in the open engagements u
// sees. Those wait for u as a review waits for a reviewer.
func (s *Server) staleRows(u config.User, engs []store.Engagement) ([]index.Row, error) {
	var rows []index.Row
	if s.flow().Simple {
		vis, err := s.Store.Visible(u)
		if err != nil {
			return nil, err
		}
		open := map[string]bool{}
		for _, e := range engs {
			if (vis == nil || vis[e.ID]) && !e.Archived {
				open[e.ID] = true
			}
		}
		if rows, err = s.Index.Rows(index.Query{Status: "draft", Author: u.Username, Visible: open}); err != nil {
			return nil, err
		}
	} else {
		v, err := s.inboxFor(u, engs)
		if err != nil {
			return nil, err
		}
		for _, k := range []workflow.Inbox{workflow.InboxReview, workflow.InboxApprove} {
			for _, r := range v.Lists[k] {
				rows = append(rows, r.row)
			}
		}
	}
	keys := make([]store.GateKey, 0, len(rows))
	for _, r := range rows {
		keys = append(keys, store.GateKey{Eng: r.EngID, Fid: r.ID, Hash: r.Full})
	}
	if len(keys) == 0 || s.Store.Linter == nil {
		return nil, nil
	}
	gates, err := s.Store.CheckGates(keys)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(rows, func(r index.Row) bool { return gates[r.EngID+"/"+r.ID] != store.GateRules }), nil
}

// inboxCheckStale starts a check, as the viewer, for the findings staleRows
// names, maxCheckStale at most. A finding that is being checked or fixed, or
// whose engagement was archived meanwhile, is left out, not an error.
func (s *Server) inboxCheckStale(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err == nil {
		err = p.inboxErr
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	rows, err := s.staleRows(p.User, p.Engagements)
	if err != nil {
		s.fail(w, err)
		return
	}
	started := 0
	for _, row := range rows {
		if started == maxCheckStale {
			break
		}
		before, had, err := s.Store.DB().LatestRun(row.EngID, row.ID)
		if err != nil {
			s.fail(w, err)
			return
		}
		// one of many: its end tells the author only of an open error
		// one of many: its end tells the author only of an open error
		run, err := s.Store.StartCheckOfMany(row.EngID, row.Dir, p.User)
		switch {
		case err == nil:
			if !had || run.ID != before.ID { // not a run that was under way
				started++
			}
		case errors.Is(err, store.ErrBusy), errors.Is(err, store.ErrArchived), errors.Is(err, store.ErrNotFound):
		default:
			s.fail(w, err)
			return
		}
	}
	// counts only, never a title
	s.log().Info("inbox: checks started for findings whose rules changed", "user", p.User.Username, "started", started, "left", len(rows)-started)
	http.Redirect(w, r, "/inbox", http.StatusSeeOther)
}

// inboxPicks are the queues with checkboxes on a director's inbox.
func inboxPicks(k workflow.Inbox) bool {
	return k == workflow.InboxApprove || k == workflow.InboxReport
}

// inboxPage is the page of rows from off; it reaches at least to row upTo
// (so a run's row further down stays visible). moved are the rows a run
// touched: they stay where they were on this page, and Load more leaves them
// out of the queue as it is now, so it goes on where this page stops.
func (s *Server) inboxPage(name workflow.Inbox, rows []inboxRow, off, upTo int, moved map[string]bool) inboxList {
	off = min(max(off, 0), len(rows))
	end := min(max(off+s.pageSize, upTo+1), len(rows))
	l := inboxList{Name: name, Heading: inboxHeadings[name], TagHead: "Severity", WhoHead: inboxWhoFor(s.flow(), name), Total: len(rows),
		Rows: rows[off:end], Offset: off, PageSize: s.pageSize}
	switch name {
	case workflow.InboxBoard:
		l.TagHead = "State"
	case workflow.InboxNotes:
		l.TagHead = "Event"
	}
	if end < len(rows) {
		next := end
		for _, r := range rows[:end] {
			if moved[r.Key] {
				next--
			}
		}
		q := url.Values{"list": {string(name)}, "offset": {strconv.Itoa(next)}}
		keys := slices.Sorted(maps.Keys(moved))
		for _, k := range keys {
			q.Add("not", k)
		}
		l.MoreURL = "/inbox?" + q.Encode()
	}
	return l
}

// without drops the rows named in not (a Load more after a run).
func without(rows []inboxRow, not []string) []inboxRow {
	if len(not) == 0 {
		return rows
	}
	return slices.DeleteFunc(slices.Clone(rows), func(r inboxRow) bool { return r.Key != "" && slices.Contains(not, r.Key) })
}

// shownQueues are the queues of v that u sees in workflow f, in the fixed
// order.
func shownQueues(f workflow.Flow, u config.User, v inboxView) []workflow.Inbox {
	own := f.Queues(u)
	var out []workflow.Inbox
	for _, k := range workflow.QueueOrder {
		if slices.Contains(own, k) || len(v.Lists[k]) > 0 || (k == workflow.InboxBoard && len(v.Board) > 0) {
			out = append(out, k)
		}
	}
	return out
}

// queueRows are the rows of queue k.
func queueRows(v inboxView, k workflow.Inbox) []inboxRow {
	switch k {
	case workflow.InboxBoard:
		return v.Board
	case workflow.InboxNotes:
		return v.Notes
	}
	return v.Lists[k]
}

// inboxListsOf lays v out for u: each queue's first page, and for a
// director the bulk bar over Ready to approve and Ready to mark reported.
// upTo keeps a run's rows on the page (by queue: the last row to show);
// moved are the rows the run touched.
func (s *Server) inboxListsOf(u config.User, v inboxView, upTo map[workflow.Inbox]int, moved map[string]bool) (inboxLists, error) {
	var out inboxLists
	if canManage(u) {
		var rows []index.Row
		for _, k := range workflow.QueueOrder {
			if inboxPicks(k) {
				for _, r := range v.Lists[k] {
					rows = append(rows, r.row)
				}
			}
		}
		b := s.inboxBar(u, rows)
		out.Bulk = &b
	}
	for _, k := range shownQueues(s.flow(), u, v) {
		l := s.inboxPage(k, queueRows(v, k), 0, upTo[k], moved)
		// the lists are capped, the counts are not
		switch k {
		case workflow.InboxBoard:
			l.Total = max(l.Total, v.BoardTotal)
		case workflow.InboxNotes:
			l.Total = max(l.Total, v.NotesTotal)
		}
		if out.Bulk != nil && inboxPicks(k) {
			l.Bulk = out.Bulk
		}
		out.Queues = append(out.Queues, l)
	}
	return out, nil
}

// inboxBar is the director's bar for the findings of the pick queues, keyed
// by "eng/dir" (the inbox spans engagements).
func (s *Server) inboxBar(u config.User, rows []index.Row) bulkBar {
	f := s.flow()
	b := bulkBar{On: true, URL: "/inbox/bulk", Cross: true, Assign: f.BulkAssign(u),
		Pick: map[string]bool{}, Acts: map[string]string{}}
	opts := f.BulkOptions(u)
	for _, o := range opts {
		b.Options = append(b.Options, menuItem(o))
	}
	for _, r := range rows {
		// Ready to approve is already filtered (withoutOpenChecks); Ready to
		// mark reported holds complete findings, past any sign-off
		b.addRow(f, u, r, opts, false)
	}
	if b.Assign {
		// across engagements: anyone who may review; each row checks its own team
		for _, c := range s.Auth.Users() {
			if workflow.AtLeast(c, "reviewer") && !c.Disabled {
				b.Users = append(b.Users, c.Username)
			}
		}
	}
	return b
}

func (s *Server) inbox(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err == nil {
		err = p.inboxErr // no queues rather than empty ones
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Nav = "inbox"
	q := r.URL.Query()
	if k := workflow.Inbox(q.Get("list")); slices.Contains(workflow.QueueOrder, k) && r.Header.Get("HX-Request") == "true" {
		off, _ := strconv.Atoi(q.Get("offset"))
		rows := queueRows(p.Inbox, k)
		// after a run: the rows it touched are on the first page already
		not := q["not"]
		moved := map[string]bool{}
		for _, n := range not {
			moved[n] = true
		}
		l := s.inboxPage(k, without(rows, not), off, 0, moved)
		if canManage(p.User) && inboxPicks(k) {
			var fr []index.Row
			for _, ir := range l.Rows {
				fr = append(fr, ir.row)
			}
			b := s.inboxBar(p.User, fr)
			l.Bulk = &b
		}
		s.exec(w, "inbox.html", "inbox_rows", l)
		return
	}
	if p.InboxLists, err = s.inboxListsOf(p.User, p.Inbox, nil, nil); err != nil {
		s.fail(w, err)
		return
	}
	stale, err := s.staleRows(p.User, p.Engagements)
	if err != nil {
		s.fail(w, err)
		return
	}
	p.InboxLists.Stale = len(stale)
	s.render(w, "inbox.html", p)
}

// inboxAfterBulk is the inbox as it was before a run, so no row moves: each
// row the run touched is refreshed from the index and shows what it is now
// (the row of its new queue, or its new state), ticked, a skipped one tinted;
// the bar carries the summary.
func (s *Server) inboxAfterBulk(u config.User, before inboxView, v bulkView) (inboxLists, error) {
	touched := map[string]bool{}
	for _, it := range v.Items {
		if it.Dir != "" {
			touched[it.Eng+"/"+it.Dir] = true
		}
	}
	fresh, loaded := map[string]index.Row{}, map[string]bool{}
	for _, it := range v.Items {
		if it.Eng == "" || loaded[it.Eng] {
			continue
		}
		loaded[it.Eng] = true
		// the run may have withdrawn some: those too
		rows, err := s.Index.Rows(index.Query{EngID: it.Eng})
		if err != nil {
			return inboxLists{}, err
		}
		gone, err := s.Index.Rows(index.Query{EngID: it.Eng, Status: workflow.Withdrawn})
		if err != nil {
			return inboxLists{}, err
		}
		for _, r := range append(rows, gone...) {
			fresh[it.Eng+"/"+r.Dir] = r
		}
	}
	after := inboxView{Lists: map[workflow.Inbox][]inboxRow{}, Board: before.Board, BoardTotal: before.BoardTotal,
		Notes: before.Notes, NotesTotal: before.NotesTotal}
	upTo := map[workflow.Inbox]int{}
	// the findings with a row in a finding queue (Pending's); a thread row
	// carries its finding's key but is not that row
	placed := map[string]bool{}
	fl := s.flow()
	for k, rows := range before.Lists {
		out := make([]inboxRow, len(rows))
		for i, ir := range rows {
			out[i] = ir
			if k != workflow.InboxThreads {
				placed[ir.Key] = true
			}
			if !touched[ir.Key] {
				continue
			}
			upTo[k] = i
			if f, ok := fresh[ir.Key]; ok && k != workflow.InboxThreads {
				out[i] = movedRow(fl, u, f, ir.EngName)
			}
		}
		after.Lists[k] = out
	}
	// a row the page showed in place after an earlier run (marked reported)
	// is in no queue of the server's: one this run brought back to a queue
	// (reverted) goes where that queue now sorts it, after the rows that
	// precede it there, so no other row moves
	var now *inboxView
	for _, key := range slices.Sorted(maps.Keys(touched)) {
		f, ok := fresh[key]
		if placed[key] || !ok || f.Meta == nil {
			continue
		}
		k := workflow.Pending(u, *f.Meta)
		if k == workflow.InboxNone || !slices.Contains(fl.Queues(u), k) {
			continue
		}
		if now == nil {
			vis, err := s.Store.Visible(u)
			if err != nil {
				return inboxLists{}, err
			}
			engs, err := s.Index.EngagementsFor(vis)
			if err != nil {
				return inboxLists{}, err
			}
			iv, err := s.inboxFor(u, engs)
			if err != nil {
				return inboxLists{}, err
			}
			now = &iv
		}
		at := slices.IndexFunc(now.Lists[k], func(ir inboxRow) bool { return ir.Key == key })
		if at < 0 {
			continue
		}
		earlier := map[string]bool{}
		for _, ir := range now.Lists[k][:at] {
			earlier[ir.Key] = true
		}
		pos := 0
		for i, ir := range after.Lists[k] {
			if earlier[ir.Key] {
				pos = i + 1
			}
		}
		after.Lists[k] = slices.Insert(after.Lists[k], pos, now.Lists[k][at])
		if last, ok := upTo[k]; ok && last >= pos {
			upTo[k] = last + 1
		} else {
			upTo[k] = max(last, pos)
		}
	}
	l, err := s.inboxListsOf(u, after, upTo, touched)
	if err != nil {
		return inboxLists{}, err
	}
	if l.Bulk != nil {
		l.Bulk.ran(v)
	}
	return l, nil
}

// movedRow is a finding's row after a run in workflow f: the row of the
// queue it is in now, or (in none) who moved it and its new state.
func movedRow(f workflow.Flow, u config.User, r index.Row, engName string) inboxRow {
	if r.Meta != nil {
		if k := workflow.Pending(u, *r.Meta); k != workflow.InboxNone {
			return findingRowFor(f, k, u, r, engName)
		}
	}
	ir := baseRow(r, engName)
	ir.Who, ir.What, ir.At, ir.Act = u.Username, workflow.StatusLabel(r.Shown), r.Since, "Open"
	return ir
}

// boardRows turns the queue's notes into inbox rows (newest first).
func boardRows(rows []boardInboxRow) []inboxRow {
	out := make([]inboxRow, 0, len(rows))
	for _, n := range rows {
		out = append(out, inboxRow{Title: n.Title, URL: n.URL, TagClass: "lead-" + n.State, Tag: n.StateLabel, EngID: n.EngID,
			EngName: n.EngName, ID: n.ID, Who: n.Who, What: n.What, At: n.At, Act: "Open", ActURL: n.URL})
	}
	return out
}
