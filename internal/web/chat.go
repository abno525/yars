package web

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"yars/internal/auth"
	"yars/internal/chat"
	"yars/internal/store"
)

type chatMsg struct {
	ID, User, Time, Section string
	Excerpt                 string // one-line plain text, shown on collapsed threads
	Anchor                  string // the section panel's id suffix, for jumping to it
	HTML                    template.HTML
}

const excerptLen = 140

// excerpt turns Markdown into a short single line: emphasis and code marks
// are dropped, whitespace collapsed, and long text cut with an ellipsis.
func excerpt(md string) string {
	s := strings.NewReplacer("**", "", "__", "", "`", "", "*", "", "#", "", ">", "").Replace(md)
	r := []rune(strings.Join(strings.Fields(s), " "))
	if len(r) > excerptLen {
		return strings.TrimSpace(string(r[:excerptLen])) + "…"
	}
	return string(r)
}

type chatThread struct {
	Root       chatMsg
	Replies    []chatMsg
	Resolved   bool
	ResolvedBy string
}

type chatItem struct {
	Event  *chatEvent
	Thread *chatThread
}

type chatEvent struct {
	User, Time, What, Text string
}

type chatView struct {
	Items                []chatItem
	Events               []chatEvent // status changes, shown in their own box above the chat
	OOB                  bool        // partial response: also refresh the status box out of band
	Open                 int
	BySection            map[string]int
	Hash                 string
	ListURL, PostURL     string
	Older                int    // messages in older threads not shown
	OlderURL             string // the whole chat
	All                  bool   // showing the whole chat
	Sections             []string
	Error, Text, Section string
	ListError            string
}

var eventText = map[string]string{
	"submit": "submitted it for verification", "return": "returned it to draft", "clear": "cleared it",
	"approve": "approved it", "reopen": "reopened it", "report": "marked it reported", "retest": "set the retest result",
}

func (s *Server) routesChat(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/f/{fid}/chat", s.chatList)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/chat", s.chatPost)
}

// chatTail is how many of the newest messages a long chat shows at first
// (whole threads: a thread is shown with all its replies or not at all).
const chatTail = 50

// chatStamp identifies the finding's chat state with one cheap query (no
// messages read); a poll whose stamp still matches is answered 204. ""
// without a database.
func (s *Server) chatStamp(ref store.FindingRef) string {
	d := s.Store.DB()
	if d == nil {
		return ""
	}
	st, err := d.ChatStamp(ref.EngID, ref.F.Meta.ID)
	if err != nil {
		return ""
	}
	return st
}

// loadChat reads the finding's whole chat.
func (s *Server) loadChat(ref store.FindingRef) ([]chat.Message, error) {
	s.chatLoads.Add(1)
	return s.Store.ChatOf(ref)
}

func (s *Server) chatMsg(m chat.Message) chatMsg {
	return chatMsg{ID: m.ID, User: m.User, Time: m.TS.Local().Format("2006-01-02 15:04"), Section: m.Section, Anchor: anchor(m.Section), Excerpt: excerpt(m.Text), HTML: s.renderMD(m.Text)}
}

// chatFor builds the chat view; stamp is chatStamp read before msgs. Unless
// all is set, only the newest threads holding chatTail messages are shown.
func (s *Server) chatFor(ref store.FindingRef, msgs []chat.Message, stamp string, all bool) chatView {
	base := findingURL(ref.EngID, ref.Dir) + "/chat"
	v := chatView{Hash: stamp, PostURL: base, Sections: s.sectionNames(ref), All: all, OlderURL: base + "?all=1"}
	q := url.Values{}
	if stamp != "" {
		q.Set("since", stamp)
	}
	if all {
		q.Set("all", "1")
	}
	v.ListURL = base
	if e := q.Encode(); e != "" {
		v.ListURL += "?" + e
	}
	v.Open, v.BySection = chat.OpenCount(msgs)
	var threads []*chat.Thread
	for _, it := range chat.Timeline(msgs) {
		if it.Event != nil {
			e := it.Event
			what := eventText[e.Event]
			if what == "" {
				what = e.Event
			}
			v.Events = append(v.Events, chatEvent{User: e.User, Time: e.TS.Local().Format("2006-01-02 15:04"), What: what, Text: e.Text})
			continue
		}
		threads = append(threads, it.Thread)
	}
	if !all {
		keep, shown := len(threads), 0
		for keep > 0 {
			n := 1 + len(threads[keep-1].Replies)
			if shown > 0 && shown+n > chatTail {
				break
			}
			shown += n
			keep--
		}
		for _, t := range threads[:keep] {
			v.Older += 1 + len(t.Replies)
		}
		threads = threads[keep:]
	}
	for _, th := range threads {
		t := &chatThread{Root: s.chatMsg(th.Root), Resolved: th.Resolved, ResolvedBy: th.ResolvedBy}
		for _, r := range th.Replies {
			t.Replies = append(t.Replies, s.chatMsg(r))
		}
		v.Items = append(v.Items, chatItem{Thread: t})
	}
	return v
}

func (s *Server) chatList(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	// the stamp first: an unchanged chat is answered without reading it
	stamp := s.chatStamp(ref)
	q := r.URL.Query()
	if since := q.Get("since"); since != "" && since == stamp {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	msgs, err := s.loadChat(ref)
	if err != nil {
		s.fail(w, err)
		return
	}
	v := s.chatFor(ref, msgs, stamp, q.Get("all") == "1")
	v.OOB = true
	s.exec(w, "finding.html", "chat_list", v)
}

func (s *Server) chatPost(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	m := chat.Message{Text: r.FormValue("text"), Section: r.FormValue("section"),
		Reply: r.FormValue("reply"), Resolves: r.FormValue("resolves"), Reopens: r.FormValue("reopens")}
	_, err := s.Store.PostChat(ref.EngID, ref.Dir, m, auth.UserFrom(r.Context()))
	stamp := s.chatStamp(ref)
	msgs, lerr := s.loadChat(ref)
	if lerr != nil {
		s.fail(w, lerr)
		return
	}
	v := s.chatFor(ref, msgs, stamp, r.FormValue("all") == "1")
	v.OOB = true
	// Thread actions (reply/resolve/reopen) refresh only the list, so a draft
	// in the main composer is never cleared by them.
	if m.Reply != "" || m.Resolves != "" || m.Reopens != "" {
		status := http.StatusOK
		if errors.Is(err, store.ErrInvalidChat) {
			status, v.ListError = http.StatusBadRequest, strings.TrimPrefix(err.Error(), store.ErrInvalidChat.Error()+": ")
		} else if err != nil {
			s.fail(w, err)
			return
		}
		s.execStatus(w, status, "finding.html", "chat_list", v)
		return
	}
	if errors.Is(err, store.ErrInvalidChat) {
		v.Error, v.Text, v.Section = strings.TrimPrefix(err.Error(), store.ErrInvalidChat.Error()+": "), m.Text, m.Section
		s.execStatus(w, http.StatusBadRequest, "finding.html", "chat_panel", v)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	s.exec(w, "finding.html", "chat_panel", v)
}
