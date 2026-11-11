package web

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"yars/internal/chat"
	"yars/internal/db"
)

func (e *env) chatIDs(t *testing.T) []string {
	t.Helper()
	msgs, err := e.srv.Store.Chat("acme", fdir)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range msgs {
		ids = append(ids, m.ID)
	}
	return ids
}

func TestChatPostAndList(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", fpath+"/chat", url.Values{"text": {"Is it reachable without login?"}, "section": {"Impact"}}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Is it reachable without login?") {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
	root := e.chatIDs(t)[0]
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"Yes, see step 2."}, "reply": {root}}, nil)
	rec = e.do(t, "bob", "POST", fpath+"/chat", url.Values{"resolves": {root}}, nil)
	b := rec.Body.String()
	if !strings.Contains(b, "Yes, see step 2.") || !strings.Contains(b, "Resolved</strong> by bob") {
		t.Fatalf("body:\n%s", b)
	}
	if got := e.lastCommit(t); got != "alice|F-001: create" {
		t.Fatalf("chat made a commit: %q", got)
	}
}

// A message shows the comment first, then who wrote it, then the section,
// which links to that section's panel.
func TestChatMessageLayout(t *testing.T) {
	e := setup(t)
	b := e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"Impact overstated?"}, "section": {"Steps to Reproduce"}}, nil).Body.String()
	msg := b[strings.Index(b, `class="msg"`):]
	text, who, sec := strings.Index(msg, "Impact overstated?"), strings.Index(msg, "<strong>bob</strong>"), strings.Index(msg, `href="#s-steps-to-reproduce"`)
	if text < 0 || !(text < who && who < sec) {
		t.Fatalf("order text %d user %d section %d:\n%s", text, who, sec, msg)
	}
}

// Hiding a resolved thread is per user and answers with the chat list.
func TestChatHideShow(t *testing.T) {
	e := setup(t)
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"Typo in step 2"}}, nil)
	id := e.chatIDs(t)[0]
	if rec := e.do(t, "alice", "POST", fpath+"/chat/"+id+"/hide", url.Values{}, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("hid an open thread: %d", rec.Code)
	}
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"resolves": {id}}, nil)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, fshort+"/chat/"+id+"/hide") || strings.Contains(b, "data-hidden") {
		t.Fatalf("resolved thread lacks hide:\n%s", b)
	}
	rec := e.do(t, "alice", "POST", fpath+"/chat/"+id+"/hide", url.Values{}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `id="chat-list"`) || !strings.Contains(rec.Body.String(), "data-hidden") ||
		!strings.Contains(rec.Body.String(), fshort+"/chat/"+id+"/show") {
		t.Fatalf("hide code %d:\n%s", rec.Code, rec.Body.String())
	}
	if b := e.do(t, "alice", "GET", fshort+"/chat", nil, nil).Body.String(); !strings.Contains(b, "data-hidden") {
		t.Fatal("hidden state not kept")
	}
	if b := e.do(t, "bob", "GET", fshort+"/chat", nil, nil).Body.String(); strings.Contains(b, "data-hidden") {
		t.Fatal("hidden for another user")
	}
	if b := e.do(t, "alice", "POST", fpath+"/chat/"+id+"/show", url.Values{}, nil).Body.String(); strings.Contains(b, "data-hidden") {
		t.Fatal("show kept it hidden")
	}
}

// A collapsed (resolved) thread still shows what the comment said.
func TestResolvedThreadShowsComment(t *testing.T) {
	e := setup(t)
	long := "**Please** rename the `login` parameter in step 2 " + strings.Repeat("and explain more ", 20)
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {long}}, nil)
	b := e.do(t, "bob", "POST", fpath+"/chat", url.Values{"resolves": {e.chatIDs(t)[0]}}, nil).Body.String()
	row := b[strings.Index(b, `class="rrow"`):]
	sum := row[:strings.Index(row, "</button>")]
	if !strings.Contains(sum, "Please rename the login parameter in step 2") || !strings.Contains(sum, "…") || strings.Contains(sum, "**") {
		t.Fatalf("summary lacks a plain excerpt:\n%s", sum)
	}
}

// Replies and resolves only refresh the list, so a draft in the main
// composer survives; polling must not wipe a half-typed reply.
func TestThreadActionsKeepComposer(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "POST", fpath+"/chat", url.Values{"text": {"root"}}, nil).Body.String()
	if !strings.Contains(b, `class="reply-form" hx-post="/e/acme/f/001/chat" hx-target="#chat-list"`) {
		t.Fatalf("reply form should target the list:\n%s", b)
	}
	root := e.chatIDs(t)[0]
	b = e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"r"}, "reply": {root}}, nil).Body.String()
	if !strings.HasPrefix(strings.TrimSpace(b), `<div id="chat-list"`) || strings.Contains(b, `id="chat-text"`) {
		t.Fatalf("reply response should be the list only:\n%s", b)
	}
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	if !strings.Contains(js, "htmx:beforeSwap") || !strings.Contains(js, "chat-list") {
		t.Fatal("no poll guard for reply drafts")
	}
}

func TestChatEscapes(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "POST", fpath+"/chat", url.Values{"text": {"look <script>alert(1)</script> here"}}, nil).Body.String()
	if strings.Contains(b, "<script>alert") {
		t.Fatalf("raw script in chat:\n%s", b)
	}
}

func TestChatPoll204(t *testing.T) {
	e := setup(t)
	e.do(t, "alice", "POST", fpath+"/chat", url.Values{"text": {"first"}}, nil)
	ref, _ := e.srv.Store.Finding("acme", fdir)
	h := e.srv.chatStamp(ref)
	if rec := e.do(t, "bob", "GET", fpath+"/chat?since="+h, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("unchanged poll code %d", rec.Code)
	}
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"second"}}, nil)
	rec := e.do(t, "alice", "GET", fpath+"/chat?since="+h, nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "second") {
		t.Fatalf("changed poll code %d", rec.Code)
	}
}

func TestChatBadRef400(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", fpath+"/chat", url.Values{"text": {"kept text"}, "reply": {"nope"}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown thread") {
		t.Fatalf("code %d body:\n%s", rec.Code, rec.Body.String())
	}
}

// chatList is the #chat-list of a page or fragment.
func chatList(t *testing.T, b string) string {
	t.Helper()
	i := strings.Index(b, `<div id="chat-list"`)
	if i < 0 {
		t.Fatalf("no chat list:\n%s", b)
	}
	b = b[i:]
	if j := strings.Index(b, `<form class="composer"`); j >= 0 {
		b = b[:j]
	}
	return b
}

// D21: status changes are read in the chat; the Status panel is gone.
func TestStatusEventsInChat(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if list := chatList(t, b); !strings.Contains(list, `<div class="chatev ev-submit"><span class="what"><strong>alice</strong> submitted it for verification</span>`) {
		t.Fatalf("no submit in the chat:\n%s", list)
	}
	if strings.Contains(b, `id="activity"`) {
		t.Fatal("the Status panel is still on the page")
	}
	// the poll answers the list alone (nothing out of band)
	if poll := e.do(t, "alice", "GET", fpath+"/chat", nil, nil).Body.String(); strings.Contains(poll, "hx-swap-oob") || !strings.Contains(poll, "ev-submit") {
		t.Fatalf("poll:\n%s", poll)
	}
}

// D21: events and threads are one timeline, in the order they happened.
func TestChatOrderMixesEventsAndThreads(t *testing.T) {
	e := setup(t)
	st := e.srv.Store
	if _, err := st.PostChat("acme", fdir, chat.Message{Text: "first note"}, wBob); err != nil {
		t.Fatal(err)
	}
	e.toVerification(t)
	if _, err := st.PostChat("acme", fdir, chat.Message{Text: "second note"}, wBob); err != nil {
		t.Fatal(err)
	}
	list := chatList(t, e.do(t, "alice", "GET", fpath+"/chat", nil, nil).Body.String())
	a, s, b := strings.Index(list, "first note"), strings.Index(list, "submitted it for verification"), strings.Index(list, "second note")
	if a < 0 || !(a < s && s < b) {
		t.Fatalf("order %d %d %d:\n%s", a, s, b, list)
	}
}

// D21: the tail is still the newest 50 messages: events do not count; those
// older than the oldest thread shown wait behind Show older.
func TestChatTailCountsMessagesOnly(t *testing.T) {
	e := setup(t)
	st, d := e.srv.Store, e.srv.Store.DB()
	for i := range 60 {
		if _, err := st.PostChat("acme", fdir, chat.Message{Text: fmt.Sprintf("m%02d", i)}, wBob); err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 { // 30 events, one after each even message
			if err := d.TxFor("acme", func(tx *db.Tx) error {
				return tx.AddMessage("acme", "F-001", chat.Message{ID: chat.NewID(), TS: time.Now(), User: "alice", Event: "submit"})
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	list := chatList(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if !strings.Contains(list, "Show older (10)") || strings.Contains(list, "<p>m09</p>") || !strings.Contains(list, "<p>m10</p>") {
		t.Fatalf("tail:\n%s", list)
	}
	// the events after m10, m12, … m58 are shown; the five before m10 are not
	if n := strings.Count(list, `class="chatev ev-submit"`); n != 25 {
		t.Fatalf("%d events shown", n)
	}
	if strings.Index(list, `class="chatev`) < strings.Index(list, "<p>m10</p>") {
		t.Fatal("an event older than the oldest thread shown")
	}
}

// D21: a Return's reason is read in the chat, on the event's row.
func TestReturnReasonShownInChat(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	e.do(t, "bob", "POST", fpath+"/action/return", url.Values{"reason": {"Add a screenshot"}}, nil)
	list := chatList(t, e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	row := between(list, `<div class="chatev ev-return">`, "</div>")
	if !strings.Contains(row, "<strong>bob</strong> returned it to draft: <span class=\"text\">Add a screenshot</span>") || !strings.Contains(row, `<span class="time">`) {
		t.Fatalf("return row:\n%s", list)
	}
}

func TestSectionCommentCount(t *testing.T) {
	e := setup(t)
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"Impact overstated?"}, "section": {"Impact"}}, nil)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	impact := b[strings.Index(b, `id="s-impact"`):]
	impact = impact[:strings.Index(impact, "</section>")]
	if !strings.Contains(impact, `class="open-count">1<`) || !strings.Contains(impact, `data-comment="Impact"`) {
		t.Fatalf("impact panel:\n%s", impact)
	}
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); !strings.Contains(b[strings.Index(b, `id="findings"`):], `class="badge">1<`) {
		t.Fatal("table lacks open count")
	}
}
