package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/chat"
)

// The fields the server caps say so to the browser: a finding's title (200,
// store.ValidTitle) and a workflow reason (4000, store.MaxReason). The
// server's own refusal stays the guard.
func TestTitleAndReasonMaxlength(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme/findings/new", nil, nil).Body.String()
	if !strings.Contains(b, `name="title" value="" required autofocus maxlength="200"`) {
		t.Errorf("the title has no maxlength:\n%s", between(b, `<label class="field">Title`, "</label>"))
	}
	if rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {strings.Repeat("x", 201)}, "mode": {"blank"}}, nil); rec.Code == http.StatusSeeOther {
		t.Error("a title of 201 characters made a finding")
	}
	e.toVerification(t)
	w := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(w, `<textarea name="reason" required rows="4" maxlength="4000">`) {
		t.Errorf("the reason has no maxlength:\n%s", between(w, `<section class="wf"`, "</section>"))
	}
}

// A double click sends one request. Plain forms: app.js marks a sent form,
// stops its second submit, and disables its buttons only after the first
// went (a disabled button is left out of the form's data); the mark goes
// after a few seconds and on pageshow, since a download stays on the page.
// The chat's htmx forms disable their button while the request is out, as
// the bulk bar does. The script half is a pin: no click is run here.
func TestDoubleSubmit(t *testing.T) {
	e := setup(t)
	if _, err := e.srv.Store.PostChat("acme", fdir, chat.Message{Text: "why?"}, wBob); err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	for _, w := range []string{`<form class="composer" hx-post="` + fshort + `/chat" hx-target="#chat" hx-swap="outerHTML" hx-disabled-elt="find button">`,
		`<form class="reply-form" hx-post="` + fshort + `/chat" hx-target="#chat-list" hx-swap="outerHTML" hx-disabled-elt="find button">`} {
		if !strings.Contains(b, w) {
			t.Errorf("the chat lacks %s:\n%s", w, between(b, `id="chat"`, "</aside>"))
		}
	}
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	for _, w := range []string{
		"if (method !== 'post' || f.hasAttribute('hx-post')) return;",
		"if (f.hasAttribute('data-sent')) { evt.preventDefault(); return; }",
		"f.setAttribute('data-sent', '');",
		// the buttons go grey after the event, so the pressed one is sent
		"yarsSentButtons(f).forEach(function (b) { if (!b.disabled) { b.disabled = true; b.yarsSent = true; b.yarsSentFocus = b === a; } });\n  }, 0);",
		// only the buttons it disabled come back (a locked-out login's stay)
		"if (!b.yarsSent) return;",
		"setTimeout(function () { yarsSentClear(f); }, yarsSentMs);",
		"window.addEventListener('pageshow', function () { document.querySelectorAll('form[data-sent]').forEach(yarsSentClear); });",
	} {
		if !strings.Contains(app, w) {
			t.Errorf("app.js lacks %s", w)
		}
	}
}
