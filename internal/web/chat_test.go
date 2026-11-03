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
	if !strings.Contains(b, "Yes, see step 2.") || !strings.Contains(b, "Resolved by bob") {
		t.Fatalf("body:\n%s", b)
	}
	if got := e.lastCommit(t); got != "bob|F-001: resolve thread" {
		t.Fatalf("commit %q", got)
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
	chat := b[strings.Index(b, `id="chat"`):]
	if !strings.Contains(chat, "returned it to draft") || !strings.Contains(chat, "Add a screenshot") {
		t.Fatalf("chat:\n%s", chat)
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
