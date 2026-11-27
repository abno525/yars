package web

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/notify"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/webhook"
)

// wireNotifications makes the notifier and the webhook service (unless
// given) and subscribes them to the store's events.
func (s *Server) wireNotifications() {
	d := s.Store.DB()
	if d == nil {
		return
	}
	base := func() string { return s.conf().BaseURL }
	if s.Notifier == nil && s.Auth != nil {
		s.Notifier = &notify.Notifier{DB: d, Users: s.Auth.Users, CanSee: s.Store.CanSee, BaseURL: base,
			MailFor: func() notify.Mailer { return notify.NewSMTP(s.conf().SMTP) },
			Simple:  func() bool { return s.flow().Simple }, Logger: s.Logger}
	}
	if s.Webhooks == nil {
		s.Webhooks = &webhook.Service{DB: d, BaseURL: base, Logger: s.Logger,
			Secrets: func() (webhook.Sealer, error) { return s.secrets() }}
	}
	s.Store.OnEvent(func(e store.Event) {
		if s.Notifier != nil {
			s.Notifier.Handle(e)
		}
		s.Webhooks.Handle(e)
	})
	if hs, err := d.Webhooks(); err == nil && len(hs) > 0 {
		s.startHooks()
	}
	s.startRetention()
}

// startHooks starts the webhook worker (once; it stops on Close).
func (s *Server) startHooks() {
	if s.Webhooks == nil {
		return
	}
	s.hooksOnce.Do(func() { go s.Webhooks.Run(s.stop) })
}

// Close stops the background workers, and a debug period of the log with
// them (its timer would hold the server).
func (s *Server) Close() {
	s.stopOnce.Do(func() {
		if s.stop != nil {
			close(s.stop)
		}
		s.stopDebug()
	})
}

// notesView is the notifications page's list: one page of rows, and the
// address of the next when there are more (the Load more row).
type notesView struct {
	Rows     []noteRow
	MoreURL  string
	PageSize int
	Later    bool // a page after the first: no empty row
}

// notesPage is how many notifications the page lists at a time.
const notesPage = 50

type noteRow struct {
	ID                                    int64
	Event, Label, Eng, Fid, Title, By, At string
	Ref                                   string // engagement · finding, or Token
	Text                                  string
	Read                                  bool
}

func (s *Server) routesNotifications(mux *http.ServeMux) {
	mux.HandleFunc("GET /notifications", s.notificationsPage)
	mux.HandleFunc("GET /notifications/{id}", s.notificationOpen)
	mux.HandleFunc("POST /notifications/{id}", s.notificationOpen)
	mux.HandleFunc("POST /notifications/read", s.notificationsRead)
	mux.HandleFunc("GET /go/search", s.goSearch)
}

func (s *Server) notificationsPage(w http.ResponseWriter, r *http.Request) {
	p, err := s.base(r, "")
	if err != nil {
		s.fail(w, err)
		return
	}
	p.Nav = "inbox" // reached from the inbox's Notifications section
	// the rows older than the notice before (the Load more row's address);
	// anything that is no number is the first page
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	before = max(before, 0)
	p.Notes.PageSize, p.Notes.Later = notesPage, before > 0
	if s.Store.DB() != nil {
		if p.Unread, err = s.Store.UnreadCount(p.User); err != nil {
			s.fail(w, err)
			return
		}
		// one more than a page, to know whether a next one exists
		l, err := s.Store.NotificationPage(p.User, false, nil, before, notesPage+1)
		if err != nil {
			s.fail(w, err)
			return
		}
		if len(l) > notesPage {
			l = l[:notesPage]
			p.Notes.MoreURL = "/notifications?before=" + strconv.FormatInt(l[notesPage-1].ID, 10)
		}
		// the findings' titles as they are now, not as they were then
		current := s.Index.CurrentTitles()
		simple := s.flow().Simple
		for _, n := range l {
			row := noteRow{ID: n.ID, Event: n.Event, Label: notify.LabelFor(n.Event, simple), Eng: n.Eng, Fid: n.Fid,
				Title: n.Title, By: n.Actor, At: when(n.TS), Text: n.Text, Read: n.Read, Ref: "Token"}
			if n.Event != notify.Token {
				row.Title, row.Ref = current(n.Eng, n.Fid, n.Title), n.Eng+" · "+n.Fid
			}
			p.Notes.Rows = append(p.Notes.Rows, row)
		}
	}
	// Load more swaps its row for the next rows
	if p.Notes.Later && r.Header.Get("HX-Request") == "true" {
		s.exec(w, "notifications.html", "note_rows", p.Notes)
		return
	}
	s.render(w, "notifications.html", p)
}

// notificationOpen opens a notification's finding; the POST (the button on
// the notifications page) also marks it read, the GET changes nothing.
func (s *Server) notificationOpen(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d := s.Store.DB()
	if err != nil || d == nil {
		http.NotFound(w, r)
		return
	}
	n, ok, err := d.NotificationByID(u.Username, id)
	if err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodPost {
		if err := d.MarkRead(u.Username, id); err != nil {
			s.fail(w, err)
			return
		}
	}
	http.Redirect(w, r, noteTarget(n), http.StatusSeeOther)
}

// notificationsRead marks every notice read; from the inbox's Notifications
// section (back=inbox) only those the section lists, and back to the inbox.
func (s *Server) notificationsRead(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	d := s.Store.DB()
	if d == nil {
		http.Redirect(w, r, "/notifications", http.StatusSeeOther)
		return
	}
	to, err := "/notifications", error(nil)
	if r.PostFormValue("back") == "inbox" {
		to, err = "/inbox", s.markNotesRead(u)
	} else {
		err = d.MarkAllRead(u.Username)
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// gotoView is the Go to palette's result list.
type gotoView struct {
	Query string
	Sent  string // the query as the field sent it: the list's stamp
	Rows  []index.Row
	Total int // matches before the cut to 20
}

// gotoLimit is how many findings Go to lists.
const gotoLimit = 20

// gotoRank orders a finding for query q: 0 exact ID or number, 1 ID
// prefix, 2 title match, -1 no match.
func gotoRank(r index.Row, q string) int {
	id := strings.ToLower(r.ID)
	num := strings.TrimLeft(strings.TrimPrefix(id, "f-"), "0")
	qn := strings.TrimLeft(strings.TrimPrefix(q, "f-"), "0")
	switch {
	case id == q || (qn != "" && num == qn && strings.Trim(qn, "0123456789") == ""):
		return 0
	case strings.HasPrefix(id, q):
		return 1
	case strings.Contains(strings.ToLower(r.Title), q):
		return 2
	}
	return -1
}

// goSearch answers the Go to palette: the user's findings whose ID or
// title match q (from the index), best first, at most 20.
func (s *Server) goSearch(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFrom(r.Context())
	sent := r.URL.Query().Get("q")
	q := strings.ToLower(strings.TrimSpace(sent))
	v := gotoView{Query: q, Sent: sent}
	if q != "" {
		vis, err := s.Store.Visible(u)
		if err != nil {
			s.fail(w, err)
			return
		}
		rows, err := s.Index.Rows(index.Query{Visible: vis})
		if err != nil {
			s.fail(w, err)
			return
		}
		type hit struct {
			r    index.Row
			rank int
		}
		var hits []hit
		for _, row := range rows {
			if k := gotoRank(row, q); k >= 0 {
				hits = append(hits, hit{row, k})
			}
		}
		slices.SortStableFunc(hits, func(a, b hit) int { return a.rank - b.rank })
		v.Total = len(hits)
		for _, h := range hits[:min(len(hits), gotoLimit)] {
			v.Rows = append(v.Rows, h.r)
		}
	}
	s.exec(w, "notifications.html", "goto_results", v)
}
