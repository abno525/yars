package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// thread posts a new thread as user and returns its id.
func (e *env) thread(t *testing.T, user, text string) string {
	t.Helper()
	before, _ := e.srv.Store.DB().Messages("acme", "F-001")
	if rec := e.do(t, user, "POST", fpath+"/chat", url.Values{"text": {text}}, map[string]string{"HX-Request": "true"}); rec.Code != 200 {
		t.Fatalf("thread %q: %d", text, rec.Code)
	}
	after, _ := e.srv.Store.DB().Messages("acme", "F-001")
	had := map[string]bool{}
	for _, m := range before {
		had[m.ID] = true
	}
	for _, m := range after {
		if !had[m.ID] && m.Text == text {
			return m.ID
		}
	}
	t.Fatalf("thread %q: not among the %d messages", text, len(after))
	return ""
}

// Every answer that redraws the chat list draws each open thread's reply
// box empty, under the id it had: the page puts a half-typed reply back by
// that id (the script below), so the id must hold through every such answer.
func TestReplyBoxesKeepTheirIDs(t *testing.T) {
	e := setup(t)
	hx := map[string]string{"HX-Request": "true"}
	a, b, c, done := e.thread(t, "bob", "thread A"), e.thread(t, "bob", "thread B"), e.thread(t, "bob", "thread C"), e.thread(t, "bob", "thread D")
	if rec := e.do(t, "bob", "POST", fpath+"/chat", url.Values{"resolves": {done}}, hx); rec.Code != 200 {
		t.Fatalf("resolve D: %d", rec.Code)
	}
	box := func(id string) string {
		return `<input name="text" id="reply-` + id + `" placeholder="Reply" aria-label="Reply">`
	}
	answers := map[string]func() string{
		"a reply in another thread": func() string {
			return e.do(t, "alice", "POST", fpath+"/chat", url.Values{"reply": {b}, "text": {"answer to B"}}, hx).Body.String()
		},
		"Resolve of another thread": func() string {
			return e.do(t, "alice", "POST", fpath+"/chat", url.Values{"resolves": {c}}, hx).Body.String()
		},
		"Hide of a resolved thread": func() string {
			return e.do(t, "alice", "POST", fpath+"/chat/"+done+"/hide", url.Values{}, hx).Body.String()
		},
		"Show of a resolved thread": func() string {
			return e.do(t, "alice", "POST", fpath+"/chat/"+done+"/show", url.Values{}, hx).Body.String()
		},
		"a new message": func() string {
			return e.do(t, "alice", "POST", fpath+"/chat", url.Values{"text": {"thread E"}}, hx).Body.String()
		},
		"Show older":     func() string { return e.do(t, "alice", "GET", fpath+"/chat?all=1", nil, hx).Body.String() },
		"a live refresh": func() string { return e.do(t, "alice", "GET", fpath+"/chat", nil, hx).Body.String() },
	}
	for _, what := range []string{"a reply in another thread", "Resolve of another thread", "Hide of a resolved thread", "Show of a resolved thread", "a new message", "Show older", "a live refresh"} {
		if body := answers[what](); !strings.Contains(body, box(a)) || !strings.Contains(body, `id="chat-list"`) {
			t.Errorf("%s: thread A's reply box is not there under its id:\n%s", what, body)
		}
	}
	// a refused reply comes back in its own box, from the server
	rec := e.do(t, "alice", "POST", fpath+"/chat", url.Values{"reply": {a}, "text": {" "}}, hx)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `id="reply-`+a+`" placeholder="Reply" aria-label="Reply" value=" "`) {
		t.Errorf("a refused reply: %d\n%s", rec.Code, rec.Body.String())
	}
	// Show older is the user's own GET on the list
	e2 := setup(t)
	for range chatTail + 1 {
		e2.thread(t, "bob", "one more")
	}
	if page := e2.do(t, "alice", "GET", fpath, nil, nil).Body.String(); !strings.Contains(page, `class="btn ghost sm w152 older" hx-get="`+fshort+`/chat?all=1" hx-target="#chat-list" hx-swap="outerHTML">Show older (`) {
		t.Errorf("Show older:\n%s", between(page, `id="chat-list"`, `class="thread"`))
	}
}

// The script that keeps half-typed replies through a swap of the chat list
// or of the whole chat. Only its text is checked here: the keeping runs in a
// browser.
func TestChatSwapKeepsRepliesScript(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	keep := jsFunc(t, js, "function yarsRepliesKeep(evt)", "\n}\n")
	for _, want := range []string{
		"t.id !== 'chat-list' && t.id !== 'chat'",     // the list's swaps and the composer's
		"#chat-list input[name=text][id^=\"reply-\"]", // every reply box, by its id
		"i.value !== ''",
		"x.status >= 200 && x.status < 300", // the box whose reply was sent comes back empty
		"document.activeElement", "selectionStart",
	} {
		if !strings.Contains(keep, want) {
			t.Errorf("yarsRepliesKeep lacks %q:\n%s", want, keep)
		}
	}
	back := jsFunc(t, js, "function yarsRepliesBack()", "\n}\n")
	for _, want := range []string{"document.getElementById(", ".value = ", "setSelectionRange("} {
		if !strings.Contains(back, want) {
			t.Errorf("yarsRepliesBack lacks %q:\n%s", want, back)
		}
	}
	for _, never := range []string{"innerHTML", "querySelector(", "localStorage", "sessionStorage"} {
		if strings.Contains(back, never) {
			t.Errorf("yarsRepliesBack uses %s:\n%s", never, back)
		}
	}
	// at once after the swap, not after the settle delay: the next key may
	// already land in the new box
	for _, want := range []string{"document.addEventListener('htmx:beforeSwap', yarsRepliesKeep);", "document.addEventListener('htmx:afterSwap', yarsRepliesBack);"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
	// the hold on the chat list is for a live event's request: the user's own
	// GET (Show older) swaps
	i := strings.Index(js, "// Live refreshes must never wipe a half-typed reply or reason")
	if i < 0 {
		t.Fatal("no hold-off for live refreshes")
	}
	hold := js[i : i+strings.Index(js[i:], "\n});")]
	for _, want := range []string{"evt.detail.requestConfig.verb !== 'get'", "t.id === 'chat-list' && !(ev && String(ev.type).indexOf('sse:') === 0)", "t.id !== 'workflow'", "t.id !== 'checks'"} {
		if !strings.Contains(hold, want) {
			t.Errorf("the hold-off lacks %q:\n%s", want, hold)
		}
	}
}
