package web

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/events"
	"yars/internal/store"
)

// The team board (Team board tab): an engagement's notes ("leads") in a
// table, the selected note's thread beside it. Its URL keeps the view
// (?state=&q=&n=, ?new=1 for the New lead form), so a reload or an inbox
// link shows the same. Every change is a POST that answers with the whole
// board; open pages refresh on the "board" event (never a finding's).

// boardEvent is the event (and the Fid) of board changes.
const boardEvent = events.Board

// leadRows caps the rows of the table; leadTail the entries of a thread.
const (
	leadRows = 200
	leadTail = 100
)

var leadStateLabel = map[string]string{"open": "Open", "analyzing": "Analyzing", "confirmed": "Confirmed", "info": "Info", "dismissed": "Dismissed"}

// teamBoardView is the board: the filters, the table and the right column
// (a note's thread, the New lead form, or an empty panel).
type teamBoardView struct {
	URL        string // /e/<eng>/board
	RefreshURL string // the same view for live refreshes (with since=)
	SSEURL     string
	State, Q   string
	Filters    []link
	Rows       []leadRow
	More       int // notes the table leaves out
	ReadOnly   bool
	Sel        *leadView
	New        *newLeadView
}

type leadRow struct {
	ID, URL, State, StateLabel string
	Title, Host, By, Activity  string
	Replies                    int
	Finding, FindingURL        string
	Sel, Off                   bool
}

// leadView is the selected note's thread panel.
type leadView struct {
	ID, PostURL           string // PostURL: /e/<eng>/board/n/<ID>/
	Title, Host, By, When string
	State, StateLabel     string
	SevLabel              string
	Finding, FindingURL   string
	CanMake, CanDismiss   bool
	CanMove, ReadOnly     bool
	Moves                 []option // Value = state, Label
	Severity              string
	Severities            []option
	DupOf, DupURL         string
	Strip                 *leadStrip // the finding it became, or why it was dismissed
	Items                 []leadItem
	Older                 int
	NoReplies             bool
	Error                 string // a refused change, in the action row
	Text, TextError       string // the composer after a refused post
	Quote                 string // Quote request: the request block the composer gets
	KeepState, KeepQ      string // the board's filter, sent along with every change
}

// leadStrip is a one-line event row: Finding F-007, Dismissed · reason …
type leadStrip struct {
	What, Text, URL, User, Time string
}

// leadItem is one timeline entry: a message (HTML) or an event strip.
type leadItem struct {
	Msg      bool
	First    bool
	User     string
	Time     string
	HTML     template.HTML
	Severity string // a severity event: shown as a chip on its row
	Strip    *leadStrip
}

// newLeadView is the New lead form.
type newLeadView struct {
	Title, Host, State, Text string
	Errs                     map[string]string
}

func (s *Server) routesTeamBoard(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/board", s.withBoard(s.teamBoard))
	mux.HandleFunc("POST /e/{eng}/board", s.withBoard(s.teamBoardCreate))
	mux.HandleFunc("GET /e/{eng}/board/n/{note}", s.withBoard(s.teamBoardNote))
	mux.HandleFunc("POST /e/{eng}/board/n/{note}/{act}", s.withBoard(s.teamBoardAct))
}

// withBoard answers 404 without a database: there is no board (and no tab).
func (s *Server) withBoard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Store.DB() == nil {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}
}

// clock is a stored time as the board shows it: the time today, the day
// before that.
func boardClock(at string, withTime bool) string {
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return at
	}
	t = t.Local()
	now := time.Now()
	if t.Year() == now.Year() && t.YearDay() == now.YearDay() {
		return t.Format("15:04")
	}
	if withTime {
		return t.Format("02 Jan 15:04")
	}
	return t.Format("02 Jan")
}

// sevLabel is a severity as the board writes it ("High").
func sevLabel(sev string) string {
	if sev == "" {
		return "Unset"
	}
	return strings.ToUpper(sev[:1]) + sev[1:]
}

// boardQuery is what a request asks of the board view: the filter, the
// search and the selected note ("" = the newest).
type boardQuery struct {
	State, Q, Note string
	New            bool
}

func boardQueryOf(r *http.Request) boardQuery {
	v := r.URL.Query()
	if r.Method == http.MethodPost {
		v = url.Values{"state": {r.FormValue("keep_state")}, "q": {r.FormValue("keep_q")}}
	}
	q := boardQuery{State: v.Get("state"), Q: strings.TrimSpace(v.Get("q")), Note: v.Get("n"), New: v.Get("new") == "1"}
	if _, ok := leadStateLabel[q.State]; !ok {
		q.State = ""
	}
	if len([]rune(q.Q)) > 200 {
		q.Q = string([]rune(q.Q)[:200])
	}
	return q
}

// url is the board URL of a view of q with note n selected.
func (q boardQuery) url(eng, n string) string {
	v := url.Values{}
	setOrDel(v, "state", q.State)
	setOrDel(v, "q", q.Q)
	setOrDel(v, "n", n)
	if e := v.Encode(); e != "" {
		return "/e/" + eng + "/board?" + e
	}
	return "/e/" + eng + "/board"
}

// boardPage is the common data of the board tab.
func (s *Server) boardPage(r *http.Request) (*page, error) {
	if s.Store.DB() == nil {
		return nil, store.ErrNoDB
	}
	return s.tabPage(r, "board")
}

// teamBoardFor builds the board for q, selecting note sel (0 = the newest
// shown), as seen by u; it marks the selected note seen.
func (s *Server) teamBoardFor(u config.User, eng string, q boardQuery, sel int) (teamBoardView, error) {
	base := "/e/" + eng + "/board"
	v := teamBoardView{URL: base, State: q.State, Q: q.Q, ReadOnly: s.Store.Archived(eng),
		SSEURL: "/events?" + url.Values{"eng": {eng}, "f": {boardEvent}}.Encode()}
	counts, err := s.Store.NoteCounts(eng)
	if err != nil {
		return v, err
	}
	total := 0
	for _, n := range counts {
		total += n
	}
	for _, st := range append([]string{""}, store.NoteStates...) {
		label, n := leadStateLabel[st], counts[st]
		if st == "" {
			label, n = "All", total
		}
		fq := q
		fq.State = st
		v.Filters = append(v.Filters, link{Key: st, Label: label, Count: n, Active: st == q.State, URL: fq.url(eng, "")})
	}
	notes, err := s.Store.Notes(eng, store.NoteFilter{State: q.State, Q: q.Q, Limit: leadRows + 1})
	if err != nil {
		return v, err
	}
	if len(notes) > leadRows {
		notes, v.More = notes[:leadRows], 1
	}
	if sel == 0 && !q.New && len(notes) > 0 {
		sel = notes[0].Num
	}
	for _, n := range notes {
		id := store.NoteID(n.Num)
		row := leadRow{ID: id, URL: q.url(eng, id), State: n.State, StateLabel: leadStateLabel[n.State], Title: n.Title, Host: n.Host, By: n.Author,
			Activity: boardClock(n.Activity, false), Replies: n.Replies, Sel: n.Num == sel && !q.New, Off: n.State == "dismissed"}
		if n.Finding != "" {
			row.Finding, row.FindingURL = n.Finding, "/e/"+eng+"/f/"+strings.TrimPrefix(n.Finding, "F-")
		}
		v.Rows = append(v.Rows, row)
	}
	if q.New {
		if !v.ReadOnly {
			v.New = &newLeadView{State: "open"}
		}
	} else if sel > 0 {
		n, err := s.Store.Note(eng, sel)
		if err != nil {
			return v, err
		}
		if err := s.Store.SeeNote(eng, sel, u); err != nil {
			return v, err
		}
		if v.Sel, err = s.leadViewOf(n, q, v.ReadOnly); err != nil {
			return v, err
		}
	}
	stamp, err := s.Store.NoteStamp(eng)
	if err != nil {
		return v, err
	}
	rq := url.Values{}
	setOrDel(rq, "state", q.State)
	setOrDel(rq, "q", q.Q)
	if v.Sel != nil {
		rq.Set("n", v.Sel.ID)
	}
	if q.New {
		rq.Set("new", "1")
	}
	rq.Set("since", strconv.FormatInt(stamp, 10))
	v.RefreshURL = base + "?" + rq.Encode()
	return v, nil
}

// leadViewOf is a note's thread panel.
func (s *Server) leadViewOf(n store.Note, q boardQuery, archived bool) (*leadView, error) {
	eng, id := n.Eng, store.NoteID(n.Num)
	linked := n.Finding != "" || n.Pending
	ro := archived || linked
	v := &leadView{ID: id, PostURL: "/e/" + eng + "/board/n/" + id + "/", Title: n.Title, Host: n.Host, By: n.Author,
		When: boardClock(n.Created, true), State: n.State, StateLabel: leadStateLabel[n.State], SevLabel: sevLabel(n.Severity), ReadOnly: ro, Severity: n.Severity, DupOf: n.DupOf,
		CanMake: !ro && (n.State == "confirmed" || n.State == "info"), CanDismiss: !ro && n.State != "dismissed", CanMove: !ro,
		KeepState: q.State, KeepQ: q.Q}
	if n.Finding != "" {
		v.Finding, v.FindingURL = n.Finding, "/e/"+eng+"/f/"+strings.TrimPrefix(n.Finding, "F-")
	}
	if n.DupOf != "" {
		v.DupURL = dupURL(eng, n.DupOf)
	}
	for _, st := range store.NoteStates {
		if st != "dismissed" {
			v.Moves = append(v.Moves, option{Value: st, Label: leadStateLabel[st]})
		}
	}
	for _, sev := range s.conf().Severities {
		v.Severities = append(v.Severities, option{Value: sev, Label: sevLabel(sev)})
	}
	host := n.Host
	if p, err := url.Parse(host); err == nil && p.Host != "" {
		host = p.Host
	}
	if host == "" {
		host = "example.test"
	}
	v.Quote = "```http\nGET / HTTP/1.1\nHost: " + host + "\n```\n"
	msgs, older, err := s.Store.NoteMessages(eng, n.Num, leadTail)
	if err != nil {
		return nil, err
	}
	v.Older = older
	// the finding it became, or why it is dismissed, heads the thread
	pinned := -1
	for i := len(msgs) - 1; i >= 0; i-- {
		m := msgs[i]
		if (m.Kind == db.KindFinding && n.Finding != "") || (m.Kind == db.KindDismiss && n.State == "dismissed") {
			pinned = i
			break
		}
	}
	replies := 0
	for i, m := range msgs {
		at := boardClock(m.TS, true)
		switch m.Kind {
		case db.KindMsg:
			v.Items = append(v.Items, leadItem{Msg: true, First: i == 0, User: m.User, Time: at, HTML: s.renderMD(m.Text)})
			if i > 0 {
				replies++
			}
			continue
		case db.KindSeverity:
			v.Items = append(v.Items, leadItem{User: m.User, Time: at, Severity: "Severity · " + sevLabel(m.Text)})
			replies++
			continue
		}
		st := &leadStrip{User: m.User, Time: at}
		switch m.Kind {
		case db.KindState:
			st.What, st.Text = "State", leadStateLabel[m.Text]
		case db.KindDismiss:
			st.What, st.Text = "Dismissed", m.Text
		case db.KindDup:
			st.What, st.Text = "Duplicate of", m.Text
			if m.Text == "" {
				st.Text = "cleared"
			} else {
				st.URL = dupURL(eng, m.Text)
			}
		case db.KindFinding:
			st.What, st.Text, st.URL = "Finding", m.Text, "/e/"+eng+"/f/"+strings.TrimPrefix(m.Text, "F-")
		default:
			continue
		}
		if i == pinned {
			v.Strip = st
			continue
		}
		if m.Kind == db.KindFinding {
			continue
		}
		v.Items = append(v.Items, leadItem{Strip: st})
		replies++
	}
	v.NoReplies = replies == 0 && older == 0
	return v, nil
}

// dupURL links a duplicate-of value of eng: a note on the board or a
// finding (both of the same engagement, checked when it was set).
func dupURL(eng, ref string) string {
	if strings.HasPrefix(ref, "F-") {
		return "/e/" + eng + "/f/" + strings.TrimPrefix(ref, "F-")
	}
	return "/e/" + eng + "/board?n=" + url.QueryEscape(ref)
}

// renderBoard answers with the board: the whole page, or the board alone
// for htmx.
func (s *Server) renderBoard(w http.ResponseWriter, r *http.Request, status int, p *page) {
	if r.Header.Get("HX-Request") == "true" {
		s.execStatus(w, status, "team_board.html", "team_board", p.TeamBoard)
		return
	}
	s.renderStatus(w, status, "team_board.html", p)
}

func (s *Server) teamBoard(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	q := boardQueryOf(r)
	sel := 0
	if q.Note != "" {
		n, ok := store.ParseNoteID(q.Note)
		if !ok {
			http.NotFound(w, r)
			return
		}
		sel = n
	}
	// a live refresh of an unchanged board: nothing to send
	if since := r.URL.Query().Get("since"); since != "" && r.Header.Get("HX-Request") == "true" {
		if st, err := s.Store.NoteStamp(eng); err == nil && strconv.FormatInt(st, 10) == since {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	u := auth.UserFrom(r.Context())
	// the board first: it marks the note it opens seen, then the tab counts
	tb, err := s.teamBoardFor(u, eng, q, sel)
	if err != nil {
		s.fail(w, err)
		return
	}
	p, err := s.boardPage(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	p.TeamBoard = tb
	s.renderBoard(w, r, http.StatusOK, p)
}

// teamBoardNote is /e/<eng>/board/n/<ID>: the board with that note open.
func (s *Server) teamBoardNote(w http.ResponseWriter, r *http.Request) {
	n, ok := store.ParseNoteID(r.PathValue("note"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	eng := r.PathValue("eng")
	if _, err := s.Store.Note(eng, n); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, boardQuery{}.url(eng, store.NoteID(n)), http.StatusSeeOther)
}

// fieldLabels name form fields in errors shown away from the field.
var fieldLabels = map[string]string{"reason": "Reason", "severity": "Severity", "dup": "Duplicate of", "state": "State", "text": "Reply"}

// changed tells open board pages that eng's board changed (IDs only).
func (s *Server) boardChanged(eng string) {
	s.Events.Publish(events.Event{Eng: eng, Fid: boardEvent, Kind: boardEvent})
}

func (s *Server) teamBoardCreate(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	if s.Store.Archived(eng) {
		s.fail(w, store.ErrArchived)
		return
	}
	u := auth.UserFrom(r.Context())
	f := newLeadView{Title: r.FormValue("title"), Host: r.FormValue("host"), State: r.FormValue("state"), Text: r.FormValue("text")}
	n, err := s.Store.CreateNote(eng, f.Title, f.Host, f.State, f.Text, u)
	q := boardQueryOf(r)
	var fe *store.FieldError
	if errors.As(err, &fe) {
		p, perr := s.boardPage(r)
		if perr != nil {
			s.fail(w, perr)
			return
		}
		q.New = true
		if p.TeamBoard, perr = s.teamBoardFor(u, eng, q, 0); perr != nil {
			s.fail(w, perr)
			return
		}
		f.Errs = map[string]string{fe.Field: fe.Msg}
		p.TeamBoard.New = &f
		s.renderBoard(w, r, http.StatusBadRequest, p)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.boardChanged(eng)
	s.boardAfter(w, r, http.StatusOK, eng, n.Num, nil)
}

// boardAfter answers a change with the board showing note num; refused,
// when set, is what the note's panel says went wrong.
func (s *Server) boardAfter(w http.ResponseWriter, r *http.Request, status int, eng string, num int, refused func(*leadView)) {
	u := auth.UserFrom(r.Context())
	tb, err := s.teamBoardFor(u, eng, boardQueryOf(r), num)
	if err != nil {
		s.fail(w, err)
		return
	}
	p, err := s.boardPage(r)
	if err != nil {
		s.fail(w, err)
		return
	}
	p.TeamBoard = tb
	if refused != nil && p.TeamBoard.Sel != nil {
		refused(p.TeamBoard.Sel)
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Push-Url", boardQuery{State: p.TeamBoard.State, Q: p.TeamBoard.Q}.url(eng, store.NoteID(num)))
	}
	s.renderBoard(w, r, status, p)
}

func (s *Server) teamBoardAct(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("eng")
	num, ok := store.ParseNoteID(r.PathValue("note"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := s.Store.Note(eng, num); err != nil {
		s.fail(w, err)
		return
	}
	if s.Store.Archived(eng) {
		s.fail(w, store.ErrArchived)
		return
	}
	u := auth.UserFrom(r.Context())
	var err error
	switch r.PathValue("act") {
	case "post":
		err = s.Store.PostNote(eng, num, r.FormValue("text"), u)
	case "state":
		err = s.Store.SetNoteState(eng, num, r.FormValue("from"), r.FormValue("to"), u)
	case "dismiss":
		err = s.Store.DismissNote(eng, num, r.FormValue("from"), r.FormValue("reason"), u)
	case "severity":
		err = s.Store.SetNoteSeverity(eng, num, r.FormValue("severity"), u)
	case "dup":
		_, err = s.Store.SetNoteDup(eng, num, r.FormValue("dup"), u)
	case "finding":
		_, err = s.Store.MakeFinding(eng, num, u)
	default:
		http.NotFound(w, r)
		return
	}
	var fe *store.FieldError
	switch {
	case err == nil:
		s.boardChanged(eng)
		s.boardAfter(w, r, http.StatusOK, eng, num, nil)
	case errors.As(err, &fe):
		s.boardAfter(w, r, http.StatusBadRequest, eng, num, func(v *leadView) {
			if fe.Field == "text" {
				v.Text, v.TextError = r.FormValue("text"), fe.Msg
				return
			}
			msg := fe.Msg
			if msg == "Required" {
				msg = fieldLabels[fe.Field] + ": required"
			}
			v.Error = msg
			if fe.Field == "dup" {
				v.DupOf = r.FormValue("dup")
			}
		})
	case errors.Is(err, store.ErrBoardStale):
		s.boardAfter(w, r, http.StatusConflict, eng, num, func(v *leadView) { v.Error = "Changed meanwhile" })
	case errors.Is(err, store.ErrBoardLocked):
		s.boardAfter(w, r, http.StatusConflict, eng, num, func(v *leadView) { v.Error = "Read only: a finding now" })
	case errors.Is(err, store.ErrInvalidBody):
		s.boardAfter(w, r, http.StatusBadRequest, eng, num, func(v *leadView) { v.Error = "The first message can't be a description" })
	case errors.Is(err, store.ErrInvalidValue):
		s.boardAfter(w, r, http.StatusBadRequest, eng, num, func(v *leadView) {
			v.Error = strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": ")
		})
	default:
		s.fail(w, err)
	}
}
