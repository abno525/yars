package web

import (
	"strings"
	"testing"
)

// The team board on the keyboard: ↓ ↑ j k move through the leads (Enter
// opens one; the link keeps its id through the board's swap), n opens New
// lead there (New finding loses it), m makes the finding and d opens Dismiss
// for the open lead. A reply or new lead being typed is guarded: a request
// that swaps the board asks first, a key that leaves the page too.
func TestTeamBoardKeys(t *testing.T) {
	e := setup(t)
	e.lead(t, "alice", "S3 listing", "", "info")
	b := e.do(t, "bob", "GET", "/e/acme/board?n=L-001", nil, nil).Body.String()
	for _, w := range []string{`<table class="table tbtable" data-arrows>`,
		`<td class="lid"><a href="/e/acme/board?n=L-001" id="lead-L-001" data-nav hx-get=`,
		`hx-push-url="true" aria-keyshortcuts="N">New lead</a>`,
		`<button class="btn primary sm w136" aria-keyshortcuts="M">Make finding</button>`,
		`<summary class="btn ghost sm w96" aria-keyshortcuts="D">Dismiss</summary>`,
		`<form class="tbcomposer" data-guard hx-post=`} {
		if !strings.Contains(b, w) {
			t.Errorf("the board lacks %s", w)
		}
	}
	if strings.Contains(between(b, "<main>", "</main>"), `/findings/new" aria-keyshortcuts="N"`) {
		t.Error("New finding keeps n on the board")
	}
	if nb := e.do(t, "bob", "GET", "/e/acme/board?new=1", nil, nil).Body.String(); !strings.Contains(nb, `<form class="tbnew" data-guard hx-post=`) {
		t.Error("the new lead form is not guarded")
	}
	app := e.do(t, "bob", "GET", "/static/app.js", nil, nil).Body.String()
	for _, w := range []string{"form[data-guard] input:not([type])", "var yarsLeaving = false;", "if (yarsLeaving || !yarsDirty(document)) return;"} {
		if !strings.Contains(app, w) {
			t.Errorf("app.js lacks %s", w)
		}
	}
	js := e.do(t, "bob", "GET", "/static/keys.js", nil, nil).Body.String()
	for _, w := range []string{"yarsConfirm('Discard changes?', 'Discard', function () { yarsLeaving = true; el.click(); });",
		"if (el.tagName === 'SUMMARY')", "function yarsPress(el)"} {
		if !strings.Contains(js, w) {
			t.Errorf("keys.js lacks %s", w)
		}
	}
	d := between(b, `id="keys"`, "</dialog>")
	for _, w := range []string{`<div class="krow" data-keys-if="a[aria-keyshortcuts~=N][href$='/board?new=1']"><dt><kbd>n</kbd></dt><dd>New lead</dd></div>`,
		`<div class="krow" data-keys-if=".tbacts [aria-keyshortcuts~=M]"><dt><kbd>m</kbd></dt><dd>Make finding</dd></div>`,
		`<div class="krow" data-keys-if=".tbacts [aria-keyshortcuts~=D]"><dt><kbd>d</kbd></dt><dd>Dismiss</dd></div>`} {
		if !strings.Contains(d, w) {
			t.Errorf("the ? list lacks %s", w)
		}
	}
}

// After review: every request of the user's that swaps the board asks while
// a reply or new lead is being typed (Make finding, severity, Set state,
// Dismiss, not only the links), except posting that text itself; a question
// raised while typing in the search box starts on Cancel; text the server
// sent back with an error counts as unsaved; m and d act on the open lead
// only while no other lead's row has focus; Back brings the leave warning
// back.
func TestTeamBoardGuardReview(t *testing.T) {
	e := setup(t)
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	wantAll(t, "app.js", app,
		"if (!q && tg && tg.id === 'board' && !live && !(evt.detail.verb !== 'get' && el && el.closest && el.closest('form[data-guard]')) && yarsDirty(tg)) {",
		"var typing = evt.detail.triggeringEvent && evt.detail.triggeringEvent.type === 'input';",
		"yarsConfirm(q, ok, function () { if (sel) sel.value = chosen; evt.detail.issueRequest(true); }, typing);",
		"if (sel) yarsSelectReset(sel);",
		"function yarsConfirm(text, ok, done, safe, no)",
		"var f = safe ? d.querySelector('button[value=cancel]') || b : b;",
		"window.addEventListener('pageshow', function () { yarsLeaving = false; });")
	if strings.Contains(app, "evt.detail.verb === 'get' && !live") {
		t.Error("the board asks for GETs only")
	}
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	wantAll(t, "keys.js", js, "if (el.closest('.tbacts') && curRow && !curRow.classList.contains('sel')) continue;", "var own = el.closest('[data-keys-scope]');")
	tplHas(t, "team_board.html", `{{if .TextError}} aria-invalid="true" data-dirty{{end}}`,
		`required{{if $e}} data-dirty{{end}}{{if index $e "title"}}`, `class="monoin"{{if $e}} data-dirty{{end}}`, `<textarea name="text" maxlength="10000" required{{if $e}} data-dirty{{end}}`)
	if d := between(e.do(t, "alice", "GET", "/", nil, nil).Body.String(), `id="keys"`, "</dialog>"); !strings.Contains(d, `<div class="krow" data-keys-if="a[data-nav], button[data-nav]"><dt><kbd>Enter</kbd></dt><dd>Open the row</dd></div>`) {
		t.Error("Enter's row shows where Enter opens nothing")
	}
}

// The inbox: ↓ ↑ move through the rows; m marks read the section of the row
// the keys moved to (none: the first that can), never another section's.
func TestInboxKeys(t *testing.T) {
	e := setup(t)
	e.lead(t, "alice", "S3 listing", "", "open")
	b := e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String()
	for _, w := range []string{`<section class="q q-notes" data-keys-scope>`, `<section class="q q-board" data-keys-scope>`,
		`<table class="table inboxt" data-arrows>`,
		`<button class="btn secondary sm w152" form="notes" formaction="/notifications/read" disabled aria-keyshortcuts="M">Mark all read</button>`,
		`<button class="btn secondary sm w152" form="notes" formaction="/inbox/board/read" aria-keyshortcuts="M">Mark all read</button>`} {
		if !strings.Contains(b, w) {
			t.Errorf("the inbox lacks %s", w)
		}
	}
	js := e.do(t, "bob", "GET", "/static/keys.js", nil, nil).Body.String()
	if !strings.Contains(js, "var own = el.closest('[data-keys-scope]');") {
		t.Error("keys.js does not keep a key to the focused row's section")
	}
	if d := between(b, `id="keys"`, "</dialog>"); !strings.Contains(d, `<div class="krow" data-keys-if=".qacts [aria-keyshortcuts~=M], form[action='/notifications/read'] [aria-keyshortcuts~=M]"><dt><kbd>m</kbd></dt><dd>Mark all read</dd></div>`) {
		t.Error("the ? list lacks m Mark all read")
	}
}

// Admin › Users: ↓ ↑ j k move through the users; on the focused row u
// unlocks, r resets the password and d disables or enables (Reset and
// Disable ask first); n goes to Add user's Username.
func TestAdminUsersKeys(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/admin/users", nil, nil).Body.String()
	for _, w := range []string{`<table class="table stable usertable" data-arrows="focus">`, `<tr data-rowkeys>`,
		`<span class="strong" title="alice" tabindex="0" data-nav id="row-user-alice">alice</span>`,
		`<button class="btn ghost sm w112" data-confirm="Reset the password of alice?" aria-keyshortcuts="R">Reset pass</button>`,
		`aria-pressed="false" data-confirm="Disable alice?" aria-keyshortcuts="D">`,
		`<input name="username" value="" pattern="[A-Za-z0-9._\-]+" required aria-keyshortcuts="N">`} {
		if !strings.Contains(b, w) {
			t.Errorf("Admin › Users lacks %s", w)
		}
	}
	src, _ := templateFS.ReadFile("templates/admin.html")
	if !strings.Contains(string(src), `title="Locked out until {{.Locked}}" aria-keyshortcuts="U">Unlock</button>`) {
		t.Error("Unlock lacks u")
	}
	js := e.do(t, "dora", "GET", "/static/keys.js", nil, nil).Body.String()
	if !strings.Contains(js, "if (el.matches('input:not([type=checkbox]):not([type=radio]), textarea, select')) { el.focus(); return; }") {
		t.Error("a key on a field does not focus it")
	}
	d := between(b, `id="keys"`, "</dialog>")
	for _, w := range []string{`<div class="krow" data-keys-if="input[name=username][aria-keyshortcuts~=N]"><dt><kbd>n</kbd></dt><dd>Add user</dd></div>`,
		`<div class="krow" data-keys-if="form[action$='/unlock'] [aria-keyshortcuts~=U]"><dt><kbd>u</kbd></dt><dd>Unlock the row</dd></div>`,
		`<div class="krow" data-keys-if="form[action$='/reset'] [aria-keyshortcuts~=R]"><dt><kbd>r</kbd></dt><dd>Reset the row's password</dd></div>`,
		`<div class="krow" data-keys-if="form[action$='/disabled'] [aria-keyshortcuts~=D], form[action$='/toggle'] [aria-keyshortcuts~=D]"><dt><kbd>d</kbd></dt><dd>Disable or enable the row</dd></div>`,
		`<div class="krow" data-keys-if="form[action$='/archive'] [aria-keyshortcuts~=A]"><dt><kbd>a</kbd></dt><dd>Archive the row</dd></div>`,
		`<div class="krow" data-keys-if="form[action$='/reopen'] [aria-keyshortcuts~=R]"><dt><kbd>r</kbd></dt><dd>Reopen the row</dd></div>`} {
		if !strings.Contains(d, w) {
			t.Errorf("the ? list lacks %s", w)
		}
	}
}
