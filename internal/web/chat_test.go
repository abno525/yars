package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
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
	if !strings.Contains(b, "Yes, see step 2.") || !strings.Contains(b, "resolved by bob") {
		t.Fatalf("body:\n%s", b)
	}
	if got := e.lastCommit(t); got != "bob|F-001: resolve thread" {
		t.Fatalf("commit %q", got)
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

// A collapsed (resolved) thread still shows what the comment said.
func TestResolvedThreadShowsComment(t *testing.T) {
	e := setup(t)
	long := "**Please** rename the `login` parameter in step 2 " + strings.Repeat("and explain more ", 20)
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {long}}, nil)
	b := e.do(t, "bob", "POST", fpath+"/chat", url.Values{"resolves": {e.chatIDs(t)[0]}}, nil).Body.String()
	sum := b[strings.Index(b, "<summary>"):strings.Index(b, "</summary>")]
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
	msgs, _ := e.srv.Store.Chat("acme", fdir)
	h := chatHash(msgs)
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

func TestReturnShowsInChat(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	e.do(t, "bob", "POST", fpath+"/action/return", url.Values{"reason": {"Add a screenshot"}}, nil)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	// status changes live in their own box above the chat, not in it
	act, chat := strings.Index(b, `id="activity"`), strings.Index(b, `id="chat"`)
	if act < 0 || chat < act {
		t.Fatalf("no status box above the chat:\n%s", b)
	}
	box := b[act:chat]
	if !strings.Contains(box, "returned it to draft") || !strings.Contains(box, "Add a screenshot") || !strings.Contains(box, "submitted it") {
		t.Fatalf("status box:\n%s", box)
	}
	if strings.Contains(b[chat:], "returned it to draft") {
		t.Fatal("status change still listed in the chat")
	}
	// the chat poll refreshes the box out of band, so others' changes show up
	poll := e.do(t, "alice", "GET", fpath+"/chat", nil, nil).Body.String()
	if !strings.Contains(poll, `id="activity" hx-swap-oob="true"`) || !strings.Contains(poll, "returned it to draft") {
		t.Fatalf("poll lacks the status box:\n%s", poll)
	}
}

func TestSectionCommentCount(t *testing.T) {
	e := setup(t)
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"Impact overstated?"}, "section": {"Impact"}}, nil)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	impact := b[strings.Index(b, `id="s-impact"`):]
	impact = impact[:strings.Index(impact, "</section>")]
	if !strings.Contains(impact, `class="open-count">1<`) || !strings.Contains(impact, `data-section="Impact"`) {
		t.Fatalf("impact panel:\n%s", impact)
	}
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); !strings.Contains(b, "1 open") {
		t.Fatal("table lacks open count")
	}
}
