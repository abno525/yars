package web

import (
	"strings"
	"testing"

	"yars/internal/chat"
)

// Confirmations are the page's own dialog, not the browser's: Discard
// changes?, hx-confirm (Clear vector, Take theirs) and data-confirm (Delete
// template, Archive) all open #confirm; the browser's is only the fallback
// of a page without it.
func TestConfirmIsInApp(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	d := between(b, `<dialog id="confirm"`, "</dialog>")
	for _, w := range []string{` class="confirmdlg" aria-labelledby="confirm-text">`, `<form method="dialog">`, `<p id="confirm-text" data-confirm-text></p>`,
		`<button value="cancel" class="btn secondary w128">Cancel</button>`, `<button value="ok" class="btn danger w128" data-confirm-ok>OK</button>`} {
		if !strings.Contains(d, w) {
			t.Errorf("the dialog lacks %s:\n%s", w, d)
		}
	}
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	if n := strings.Count(app, "window.confirm("); n != 1 {
		t.Errorf("window.confirm used %d times", n)
	}
	for _, w := range []string{"function yarsConfirm(text, ok, done)", "yarsConfirm(q, ok, function () { evt.detail.issueRequest(true); });",
		"q = 'Discard changes?'", "evt.detail.question", "yarsConfirm(c.getAttribute('data-confirm')"} {
		if !strings.Contains(app, w) {
			t.Errorf("app.js lacks %s", w)
		}
	}
	// a click outside does not close it (the second click of a double-click
	// on Archive would)
	if strings.Contains(app, "d.open && evt.target === d) d.close()") {
		t.Error("a click on the backdrop closes the dialog")
	}
	// a form's submit button asks with data-confirm (htmx reads hx-confirm
	// from the form only, and the dialog's focus would drop the button from
	// the request): Clear vector
	src, _ := templateFS.ReadFile("templates/cvss.html")
	if !strings.Contains(string(src), `value="clear" data-confirm="Remove the CVSS vector?">Clear vector</button>`) {
		t.Error("Clear vector does not ask")
	}
	if css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String(); !strings.Contains(css, "dialog.confirmdlg {") {
		t.Error("no style for the dialog")
	}
}

// The chat on the keyboard: with the chat selected, j k ↓ ↑ pick a comment
// (a thread, tinted as a list row), r resolves it, and any key no shortcut
// takes starts its reply (a new message with none picked); ↓ ↑ with nothing
// selected pick the first panel; Ctrl+H hides or shows the chat.
func TestChatKeys(t *testing.T) {
	e := setup(t)
	m, err := e.srv.Store.PostChat("acme", fdir, chat.Message{Text: "why?"}, wBob)
	if err != nil {
		t.Fatal(err)
	}
	b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, `<div class="thread" id="t-`+m.ID+`" data-thread="`+m.ID+`">`) {
		t.Errorf("the thread is not marked:\n%s", between(b, `id="chat-list"`, "</form>"))
	}
	if !strings.Contains(b, `data-chat-toggle aria-controls="side" aria-expanded="true" aria-keyshortcuts="Control+H">`) {
		t.Error("the chat toggle lacks Ctrl+H")
	}
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	for _, w := range []string{"function yarsThreadStep(d)", "case 'J': return side ? yarsThreadStep(1) || true : yarsStep(1);", "case 'K': return side ? yarsThreadStep(-1) || true : yarsStep(-1);",
		"case 'ArrowDown': return side ? yarsThreadStep(1) : yarsStep(1);", "case 'ArrowUp': return side ? yarsThreadStep(-1) : yarsStep(-1);",
		"function yarsResolveKey()", "if (key === 'R' && (yarsResolveKey() || yarsThread()))", "function yarsWrite(evt)", "yarsFire(key) || yarsBulkFire(key) || yarsWrite(evt)",
		"key === 'Control+H'",
		// a hidden panel is not selected: keys never act in a hidden chat
		"return p && p.hasAttribute('data-kpanel') && p.getClientRects().length > 0 ? p : null;",
		// in the chat j k h are its own, even with nothing to step to
		"case 'H': return yarsBack() || side;"} {
		if !strings.Contains(js, w) {
			t.Errorf("keys.js lacks %s", w)
		}
	}
	if css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String(); !strings.Contains(css, "#chat-list .thread[data-tsel] { background: var(--mark-bg); }") {
		t.Error("a picked comment is not tinted")
	}
	g := between(b, `data-keys-group="chat"`, "</section>")
	for _, w := range []string{`<div class="krow" data-keys-if="#chat-list .thread"><dt><kbd>j</kbd><kbd>k</kbd><kbd>↓</kbd><kbd>↑</kbd></dt><dd>Next or previous comment</dd></div>`,
		`<div class="krow" data-keys-if="#chat-list .thread-tools [name=resolves]"><dt><kbd>r</kbd></dt><dd>Resolve the comment</dd></div>`,
		`<div class="krow" data-keys-if="#chat-text"><dt><kbd>Other keys</kbd></dt><dd>Write a reply</dd></div>`,
		`<div class="krow" data-keys-for="Control+H"><dt><kbd>Ctrl+H</kbd></dt><dd>Hide or show the chat</dd></div>`} {
		if !strings.Contains(g, w) {
			t.Errorf("the Chat group lacks %s:\n%s", w, g)
		}
	}
}
