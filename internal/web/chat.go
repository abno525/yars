package web

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/store"
)

type chatMsg struct {
	ID, User, Time, Section string
	Excerpt                 string // one-line plain text, shown on collapsed threads
	Anchor                  string // the section panel's id suffix, for jumping to it
	HTML                    template.HTML
	AI                      bool // the AI wrote it for User (Fix with AI)
}

const excerptLen = 140

// The Markdown structure an excerpt drops: quote markers, headings and code
// fences at the start of a line, and paired emphasis and code marks. Any other
// character is the text's own ("<script>", "C#", "#12", "2*3", "a__b") and
// stays; html/template escapes it.
var (
	exFence  = regexp.MustCompile("^\\s*(```|~~~)\\S*\\s*$")
	exQuote  = regexp.MustCompile(`^\s*(>\s?)+`)
	exHead   = regexp.MustCompile(`^\s*#{1,6}\s+`)
	exStrong = regexp.MustCompile(`(^|[^\w*])\*\*([^*\s](?:[^*]*[^*\s])?)\*\*($|[^\w*])`)
	exUnder  = regexp.MustCompile(`(^|[^\w_])__([^_\s](?:[^_]*[^_\s])?)__($|[^\w_])`)
	exEm     = regexp.MustCompile(`(^|[^\w*])\*([^*\s](?:[^*]*[^*\s])?)\*($|[^\w*])`)
	exCode   = regexp.MustCompile("`([^`]+)`")
)

// excerpt turns Markdown into a short single line: quote markers, heading
// marks and paired emphasis and code marks are dropped, whitespace
// collapsed, and long text cut with an ellipsis.
func excerpt(md string) string {
	lines := strings.Split(md, "\n")
	for i, l := range lines {
		l = exQuote.ReplaceAllString(l, "")
		l = exFence.ReplaceAllString(l, "")
		l = exHead.ReplaceAllString(l, "")
		l = exCode.ReplaceAllString(l, "$1")
		// a match takes the character after it, so neighbours ("**a**
		// **b**") need another pass
		for range 4 {
			before := l
			l = exStrong.ReplaceAllString(l, "$1$2$3")
			l = exUnder.ReplaceAllString(l, "$1$2$3")
			l = exEm.ReplaceAllString(l, "$1$2$3")
			if l == before {
				break
			}
		}
		lines[i] = l
	}
	r := []rune(strings.Join(strings.Fields(strings.Join(lines, "\n")), " "))
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
	// Hidden: the current user hid this resolved thread. HideURL and
	// ShowURL (POST) answer with the chat list; set on resolved threads.
	Hidden           bool
	HideURL, ShowURL string
}

type chatItem struct {
	Event  *chatEvent
	Thread *chatThread
}

type chatEvent struct {
	User, Time, What, Text string
	Kind                   string // the workflow event (submit, return, …): the marker colour
	URL                    string // a merge event: the merged finding itself (its page leads here otherwise)
}

type chatView struct {
	// Items is the timeline in order: status changes (Event) and threads
	// (D21: status changes are read in the chat)
	Items                []chatItem
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
	ReplyTo, ReplyText   string // a refused reply: its thread and its text, back in that box
	ReadOnly             bool   // archived engagement: no composer, replies or resolving
}

var eventText = map[string]string{
	"submit": "submitted it for verification", "return": "returned it to draft", "clear": "signed it off",
	"approve": "approved it", "reopen": "reverted it to verification", "report": "marked it reported", "unreport": "reverted it to complete", "retest": "set the retest result",
	"withdraw": "withdrew it", "revise": "restored it", "take_back": "took it back to draft", store.EventCheckFixed: "found a check fixed", store.EventMerge: "merged in",
	"complete": "completed it",
}

// eventTextFor says in the chat what a workflow event did, as the workflow
// (simple or not) names it: the simple workflow's revert goes back to
// draft. An unknown event is its own name.
func eventTextFor(ev string, simple bool) string {
	if simple && ev == "reopen" {
		return "reverted it to draft"
	}
	if what := eventText[ev]; what != "" {
		return what
	}
	return ev
}

func (s *Server) routesChat(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/f/{fid}/chat", s.chatList)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/chat", s.chatPost)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/chat/{thread}/hide", s.chatHide(true))
	mux.HandleFunc("POST /e/{eng}/f/{fid}/chat/{thread}/show", s.chatHide(false))
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
	return chatMsg{ID: m.ID, User: m.User, Time: m.TS.Local().Format("2006-01-02 15:04"), Section: m.Section, Anchor: anchor(m.Section), Excerpt: excerpt(m.Text), HTML: s.renderMD(m.Text), AI: m.Kind == chat.KindAI}
}

// hiddenFor returns the resolved threads of the finding the request's user
// hid (none on error or without a database).
func (s *Server) hiddenFor(r *http.Request, ref store.FindingRef) map[string]bool {
	d := s.Store.DB()
	if d == nil {
		return nil
	}
	h, err := d.ChatHidden(auth.UserFrom(r.Context()).Username, ref.EngID, ref.F.Meta.ID)
	if err != nil {
		return nil
	}
	return h
}

// liveSection reports whether a thread's section has a panel on the finding
// page: "" (general) has none to miss; any other name must be one of names
// (the file's sections, the configured ones and the panels a comment can
// point at).
func liveSection(names []string, section string) bool {
	return section == "" || slices.Contains(names, section)
}

// chatFor builds the chat view; stamp is chatStamp read before msgs. Unless
// all is set, only the newest threads holding chatTail messages are shown.
// hidden are the threads the viewer hid.
func (s *Server) chatFor(ref store.FindingRef, msgs []chat.Message, stamp string, all bool, hidden map[string]bool) chatView {
	base := findingURL(ref.EngID, ref.Dir) + "/chat"
	v := chatView{Hash: stamp, PostURL: base, Sections: append(s.sectionNames(ref), store.PanelTargets...), All: all, OlderURL: base + "?all=1",
		ReadOnly: s.Store.Archived(ref.EngID)}
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
	// a thread on a section that is gone from the file and is not configured
	// (a push removed its heading, Admin › Structure its name) is a general
	// one here: no panel has its anchor or shows its count. The stored
	// message keeps its section, so the thread is back on its panel when the
	// section is.
	for name, n := range v.BySection {
		if !liveSection(v.Sections, name) {
			v.BySection[""] += n
			delete(v.BySection, name)
		}
	}
	items := chat.Timeline(msgs)
	var threads []int // the threads' places in items
	for i, it := range items {
		if it.Thread != nil {
			threads = append(threads, i)
		}
	}
	// the newest threads holding chatTail messages, whole; events do not
	// count, and those older than the oldest thread shown wait with it
	from, simple := 0, s.flow().Simple
	if !all {
		keep, shown := len(threads), 0
		for keep > 0 {
			n := 1 + len(items[threads[keep-1]].Thread.Replies)
			if shown > 0 && shown+n > chatTail {
				break
			}
			shown += n
			keep--
		}
		for _, i := range threads[:keep] {
			v.Older += 1 + len(items[i].Thread.Replies)
		}
		if keep > 0 {
			from = threads[keep]
		}
	}
	for _, it := range items[from:] {
		if e := it.Event; e != nil {
			what := eventTextFor(e.Event, simple)
			ev := &chatEvent{User: e.User, Time: e.TS.Local().Format("2006-01-02 15:04"), What: what, Text: e.Text, Kind: e.Event}
			// the store wrote the source's ID as the merge event's text
			if e.Event == store.EventMerge && store.ValidID(e.Text) {
				ev.URL = findingURL(ref.EngID, e.Text) + "?" + sourceParam + "=1"
			}
			v.Items = append(v.Items, chatItem{Event: ev})
			continue
		}
		th := it.Thread
		t := &chatThread{Root: s.chatMsg(th.Root), Resolved: th.Resolved, ResolvedBy: th.ResolvedBy}
		if !liveSection(v.Sections, th.Root.Section) {
			t.Root.Section, t.Root.Anchor = "", ""
		}
		if th.Resolved {
			t.Hidden = hidden[th.Root.ID]
			t.HideURL, t.ShowURL = base+"/"+th.Root.ID+"/hide", base+"/"+th.Root.ID+"/show"
		}
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
	v := s.chatFor(ref, msgs, stamp, q.Get("all") == "1", s.hiddenFor(r, ref))
	s.exec(w, "finding.html", "chat_list", v)
}

// chatHide hides (on) or shows a resolved thread for the current user and
// answers with the chat list.
func (s *Server) chatHide(on bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ref, ok := s.cvssRef(w, r)
		if !ok {
			return
		}
		err := s.Store.HideThread(ref.EngID, ref.Dir, r.PathValue("thread"), on, auth.UserFrom(r.Context()))
		status := http.StatusOK
		var listErr string
		if errors.Is(err, store.ErrInvalidChat) {
			status, listErr = http.StatusBadRequest, strings.TrimPrefix(err.Error(), store.ErrInvalidChat.Error()+": ")
		} else if err != nil {
			s.fail(w, err)
			return
		}
		stamp := s.chatStamp(ref)
		msgs, err := s.loadChat(ref)
		if err != nil {
			s.fail(w, err)
			return
		}
		v := s.chatFor(ref, msgs, stamp, r.FormValue("all") == "1", s.hiddenFor(r, ref))
		v.ListError = listErr
		s.execStatus(w, status, "finding.html", "chat_list", v)
	}
}

func (s *Server) chatPost(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	m := chat.Message{Text: r.FormValue("text"), Section: r.FormValue("section"),
		Reply: r.FormValue("reply"), Resolves: r.FormValue("resolves"), Reopens: r.FormValue("reopens")}
	u := auth.UserFrom(r.Context())
	_, err := s.Store.PostChat(ref.EngID, ref.Dir, m, u)
	// the message is posted; the writer hears whom its @names did not reach
	unheard := ""
	if err == nil && m.Resolves == "" && m.Reopens == "" {
		unheard = store.UnheardLine(s.Store.Unheard(ref.EngID, m.Text, u))
	}
	stamp := s.chatStamp(ref)
	msgs, lerr := s.loadChat(ref)
	if lerr != nil {
		s.fail(w, lerr)
		return
	}
	v := s.chatFor(ref, msgs, stamp, r.FormValue("all") == "1", s.hiddenFor(r, ref))
	// Thread actions (reply/resolve/reopen) refresh only the list, so a draft
	// in the main composer is never cleared by them.
	if m.Reply != "" || m.Resolves != "" || m.Reopens != "" {
		status := http.StatusOK
		if errors.Is(err, store.ErrInvalidChat) {
			status, v.ListError = http.StatusBadRequest, strings.TrimPrefix(err.Error(), store.ErrInvalidChat.Error()+": ")
			v.ReplyTo, v.ReplyText = m.Reply, m.Text
		} else if err != nil {
			s.fail(w, err)
			return
		} else {
			v.ListError = unheard
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
	v.Error = unheard
	s.exec(w, "finding.html", "chat_panel", v)
}
