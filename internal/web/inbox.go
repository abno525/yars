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
	Heading  string
	Total    int // rows in the whole list
	Rows     []inboxRow
	Offset   int
	PageSize int
	MoreURL  string // the next page ("" = no more)
	Director bool   // rows can be selected for bulk actions
	// after a bulk action: the outcome per "eng/ID", and the label of a
	// success
	Results map[string]*bulkItem
	Done    string
}

// inboxLists are the inbox page's lists, one page each.
type inboxLists struct {
	Review, Approve, Returned inboxList
	Director                  bool
	Unlisted                  *bulkView // bulk results for findings in no list
}

var inboxHeadings = map[string]string{"review": "Awaiting my review", "approve": "Ready to approve", "returned": "Returned to me"}

// inboxPage is the page of rows from off; it reaches at least to row upTo
// (so a bulk result further down stays visible).
func (s *Server) inboxPage(name string, rows []inboxRow, off, upTo int, director bool) inboxList {
	off = min(max(off, 0), len(rows))
	end := min(max(off+s.pageSize, upTo+1), len(rows))
	l := inboxList{Name: name, Heading: inboxHeadings[name], Total: len(rows), Rows: rows[off:end], Offset: off,
		PageSize: s.pageSize, Director: director}
	if end < len(rows) {
		l.MoreURL = "/inbox?list=" + name + "&offset=" + strconv.Itoa(end)
	}
	return l
}

func (s *Server) inboxListsOf(v inboxView, director bool) inboxLists {
	return inboxLists{Review: s.inboxPage("review", v.Review, 0, 0, director),
		Approve:  s.inboxPage("approve", v.Approve, 0, 0, director),
		Returned: s.inboxPage("returned", v.Returned, 0, 0, director), Director: director}
}

// reviewerChoices are the accounts the bulk picker offers.
func (s *Server) reviewerChoices() []config.User {
	var out []config.User
	for _, u := range s.Auth.Users() {
		if workflow.AtLeast(u, "reviewer") {
			out = append(out, u)
		}
	}
	return out
}

func (s *Server) inbox(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Nav = "inbox"
	q := r.URL.Query()
	off, _ := strconv.Atoi(q.Get("offset"))
	lists := map[string][]inboxRow{"review": p.Inbox.Review, "approve": p.Inbox.Approve, "returned": p.Inbox.Returned}
	if rows, ok := lists[q.Get("list")]; ok && r.Header.Get("HX-Request") == "true" {
		s.exec(w, "inbox.html", "inbox_rows", s.inboxPage(q.Get("list"), rows, off, 0, p.CanManage))
		return
	}
	p.InboxLists = s.inboxListsOf(p.Inbox, p.CanManage)
	if p.CanManage {
		p.Users = s.reviewerChoices()
	}
	s.render(w, "inbox.html", p)
}

// inboxAfterBulk is the inbox as it was before a bulk action, each acted-on
// row refreshed and carrying its result, so no row moves; findings in no
// list get a result table of their own.
func (s *Server) inboxAfterBulk(before inboxView, v bulkView) (inboxLists, error) {
	res := map[string]*bulkItem{}
	for i := range v.Items {
		res[v.Items[i].Key] = &v.Items[i]
	}
	fresh, loaded := map[string]index.Row{}, map[string]bool{}
	for _, it := range v.Items {
		if it.Eng == "" || loaded[it.Eng] {
			continue
		}
		loaded[it.Eng] = true
		rows, err := s.Index.Rows(index.Query{EngID: it.Eng})
		if err != nil {
			return inboxLists{}, err
		}
		for _, r := range rows {
			fresh[it.Eng+"/"+r.ID] = r
		}
	}
	listed := map[string]bool{}
	page := func(name string, rows []inboxRow) inboxList {
		upTo := 0
		out := make([]inboxRow, len(rows))
		for i, r := range rows {
			k := r.EngID + "/" + r.ID
			out[i] = r
			if res[k] == nil {
				continue
			}
			listed[k], upTo = true, i
			if f, ok := fresh[k]; ok {
				out[i].Row = f
			}
		}
		l := s.inboxPage(name, out, 0, upTo, true)
		l.Results, l.Done = res, bulkDone[v.Action]
		return l
	}
	l := inboxLists{Review: page("review", before.Review), Approve: page("approve", before.Approve),
		Returned: page("returned", before.Returned), Director: true}
	rest := bulkView{Action: v.Action}
	for _, it := range v.Items {
		if !listed[it.Key] {
			rest.Items = append(rest.Items, it)
		}
	}
	if len(rest.Items) > 0 {
		l.Unlisted = &rest
	}
	return l, nil
}
