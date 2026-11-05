package web

import (
	"net/http"
	"strconv"
	"sync"

	"yars/internal/config"
	"yars/internal/index"
	"yars/internal/store"
	"yars/internal/workflow"
)

type inboxRow struct {
	EngName string
	index.Row
}

type inboxView struct {
	Review, Approve, Returned []inboxRow
}

func (v inboxView) Count() int { return len(v.Review) + len(v.Approve) + len(v.Returned) }

// inboxCache holds each user's inbox for one index generation; views are
// shared between requests, so they are read only.
type inboxCache struct {
	mu     sync.Mutex
	gen    uint64
	byUser map[string]inboxView
	builds int // classifications done (for tests)
}

// inboxFor classifies every finding across engagements for u, once per
// index generation.
func (s *Server) inboxFor(u config.User, engs []store.Engagement) (inboxView, error) {
	gen, err := s.Index.Gen()
	if err != nil {
		return inboxView{}, err
	}
	key := u.Username + "\x00" + u.Role
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
	rows, err := s.Index.Rows(index.Query{Sort: "severity"})
	if err != nil {
		return inboxView{}, err
	}
	names := map[string]string{}
	for _, e := range engs {
		names[e.ID] = e.Name
	}
	for _, r := range rows {
		ir := inboxRow{EngName: names[r.EngID], Row: r}
		switch workflow.Pending(u, *r.Meta) {
		case workflow.InboxReview:
			v.Review = append(v.Review, ir)
		case workflow.InboxApprove:
			v.Approve = append(v.Approve, ir)
		case workflow.InboxReturned:
			v.Returned = append(v.Returned, ir)
		}
	}
	c.mu.Lock()
	c.builds++
	if c.gen == gen {
		c.byUser[key] = v
	}
	c.mu.Unlock()
	return v, nil
}

// inboxList is one page of an inbox list; "Load more" appends the next.
type inboxList struct {
	Name     string // review | approve | returned
	Rows     []inboxRow
	Offset   int
	PageSize int
	MoreURL  string // the next page ("" = no more)
}

// inboxLists are the inbox page's lists, one page each.
type inboxLists struct {
	Review, Approve, Returned inboxList
}

func (s *Server) inboxPage(name string, rows []inboxRow, off int) inboxList {
	off = min(max(off, 0), len(rows))
	end := min(off+s.pageSize, len(rows))
	l := inboxList{Name: name, Rows: rows[off:end], Offset: off, PageSize: s.pageSize}
	if end < len(rows) {
		l.MoreURL = "/inbox?list=" + name + "&offset=" + strconv.Itoa(end)
	}
	return l
}

func (s *Server) inbox(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	q := r.URL.Query()
	off, _ := strconv.Atoi(q.Get("offset"))
	lists := map[string][]inboxRow{"review": p.Inbox.Review, "approve": p.Inbox.Approve, "returned": p.Inbox.Returned}
	if rows, ok := lists[q.Get("list")]; ok && r.Header.Get("HX-Request") == "true" {
		s.exec(w, "inbox.html", "inbox_rows", s.inboxPage(q.Get("list"), rows, off))
		return
	}
	p.InboxLists = inboxLists{Review: s.inboxPage("review", p.Inbox.Review, 0),
		Approve: s.inboxPage("approve", p.Inbox.Approve, 0), Returned: s.inboxPage("returned", p.Inbox.Returned, 0)}
	s.render(w, "inbox.html", p)
}
