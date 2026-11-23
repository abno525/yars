package web

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"yars/internal/auth"
	"yars/internal/index"
	"yars/internal/notify"
	"yars/internal/store"
	"yars/internal/webhook"
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
			Simple:  func() bool { return s.flow().Simple }}
	}
	if s.Webhooks == nil {
		s.Webhooks = &webhook.Service{DB: d, BaseURL: base,
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

// Close stops the background workers.
func (s *Server) Close() {
	s.stopOnce.Do(func() {
		if s.stop != nil {
			close(s.stop)
		}
	})
}

// notesView is the notifications page.
type notesView struct {
	Rows []noteRow
}

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
	if s.Store.DB() != nil {
		if p.Unread, err = s.Store.UnreadCount(p.User); err != nil {
			s.fail(w, err)
			return
		}
		l, err := s.Store.Notifications(p.User, false, 200)
		if err != nil {
			s.fail(w, err)
			return
		}
		// the findings' titles as they are now, not as they were then
		current := s.Index.CurrentTitles()
		for _, n := range l {
			row := noteRow{ID: n.ID, Event: n.Event, Label: notify.Label(n.Event), Eng: n.Eng, Fid: n.Fid,
				Title: n.Title, By: n.Actor, At: when(n.TS), Text: n.Text, Read: n.Read, Ref: "Token"}
			if n.Event != notify.Token {
				row.Title, row.Ref = current(n.Eng, n.Fid, n.Title), n.Eng+" · "+n.Fid
			}
			p.Notes.Rows = append(p.Notes.Rows, row)
		}
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
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	v := gotoView{Query: q}
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
