package web

import (
	"errors"
	"html/template"
	"net/http"
	"strings"

	"yars/internal/auth"
	"yars/internal/chat"
	"yars/internal/store"
)

type chatMsg struct {
	ID, User, Time, Section string
	HTML                    template.HTML
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
	Open                 int
	BySection            map[string]int
	Hash                 string
	ListURL, PostURL     string
	Sections             []string
	Error, Text, Section string
}

var eventText = map[string]string{
	"submit": "submitted it for verification", "return": "returned it to draft", "clear": "cleared it",
	"approve": "approved it", "reopen": "reopened it", "report": "marked it reported",
}

func (s *Server) routesChat(mux *http.ServeMux) {
	mux.HandleFunc("GET /e/{eng}/f/{fid}/chat", s.chatList)
	mux.HandleFunc("POST /e/{eng}/f/{fid}/chat", s.chatPost)
}

// chatHash identifies the chat state; polling skips the swap when unchanged.
func chatHash(msgs []chat.Message) string {
	ids := make([]string, len(msgs))
	for i, m := range msgs {
		ids[i] = m.ID
	}
	return store.BodyHash(strings.Join(ids, ","))
}

func (s *Server) chatMsg(m chat.Message) chatMsg {
	return chatMsg{ID: m.ID, User: m.User, Time: m.TS.Local().Format("2006-01-02 15:04"), Section: m.Section, HTML: s.renderMD(m.Text)}
}

func (s *Server) chatFor(ref store.FindingRef, msgs []chat.Message) chatView {
	base := "/e/" + ref.EngID + "/f/" + ref.Dir + "/chat"
	v := chatView{Hash: chatHash(msgs), PostURL: base, Sections: s.sectionNames(ref)}
	v.ListURL = base + "?since=" + v.Hash
	v.Open, v.BySection = chat.OpenCount(msgs)
	for _, it := range chat.Timeline(msgs) {
		if it.Event != nil {
			e := it.Event
			what := eventText[e.Event]
			if what == "" {
				what = e.Event
			}
			v.Items = append(v.Items, chatItem{Event: &chatEvent{User: e.User, Time: e.TS.Local().Format("2006-01-02 15:04"), What: what, Text: e.Text}})
			continue
		}
		t := &chatThread{Root: s.chatMsg(it.Thread.Root), Resolved: it.Thread.Resolved, ResolvedBy: it.Thread.ResolvedBy}
		for _, r := range it.Thread.Replies {
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
	msgs, err := s.Store.Chat(ref.EngID, ref.Dir)
	if err != nil {
		s.fail(w, err)
		return
	}
	if since := r.URL.Query().Get("since"); since != "" && since == chatHash(msgs) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.exec(w, "finding.html", "chat_list", s.chatFor(ref, msgs))
}

func (s *Server) chatPost(w http.ResponseWriter, r *http.Request) {
	ref, ok := s.cvssRef(w, r)
	if !ok {
		return
	}
	m := chat.Message{Text: r.FormValue("text"), Section: r.FormValue("section"),
		Reply: r.FormValue("reply"), Resolves: r.FormValue("resolves"), Reopens: r.FormValue("reopens")}
	_, err := s.Store.PostChat(ref.EngID, ref.Dir, m, auth.UserFrom(r.Context()))
	msgs, lerr := s.Store.Chat(ref.EngID, ref.Dir)
	if lerr != nil {
		s.fail(w, lerr)
		return
	}
	v := s.chatFor(ref, msgs)
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
