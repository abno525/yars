package web

import (
	"strings"
	"testing"

	"yars/internal/db"
)

// wantAll fails for each want b lacks.
func wantAll(t *testing.T, where, b string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(b, w) {
			t.Errorf("%s lacks %s", where, w)
		}
	}
}

// tplHas fails for each want the template file lacks.
func tplHas(t *testing.T, file string, wants ...string) {
	t.Helper()
	src, err := templateFS.ReadFile("templates/" + file)
	if err != nil {
		t.Fatal(err)
	}
	wantAll(t, file, string(src), wants...)
}

// Settings › Tokens: n New token (the Developers page's too); ↓ ↑ move
// through the tokens from a focused one (j k step Settings' panels) and r
// revokes the focused one, asking first; removing a connection asks too.
func TestSettingsTokenKeys(t *testing.T) {
	e := setup(t)
	if _, err := e.srv.Store.DB().CreateToken("alice", "h-abcd", "abcd", db.TokenSpec{Name: "laptop", Kind: db.TokenMCP, Scopes: []string{db.ScopeAll}}); err != nil {
		t.Fatal(err)
	}
	wantAll(t, "/settings", e.do(t, "alice", "GET", "/settings", nil, nil).Body.String(),
		`<a class="btn primary sm w112" href="/settings/tokens/new" aria-keyshortcuts="N">New token</a>`,
		`<table class="table stable tokentable" data-arrows="focus">`, `<tr data-rowkeys>`,
		`<span class="strong" title="laptop" tabindex="0" data-nav id="row-token-`,
		`<button class="btn danger sm w96" data-confirm="Revoke laptop?" aria-keyshortcuts="R">Revoke</button>`)
	tplHas(t, "settings.html", `data-confirm="Remove the {{.Label}} key?">Remove</button>`)
	wantAll(t, "/docs/mcp", e.do(t, "alice", "GET", "/docs/mcp", nil, nil).Body.String(),
		`<a class="btn primary w128" href="/settings/tokens/new" aria-keyshortcuts="N">New token</a>`)
}

// Templates: n goes to the new template's title; ↓ ↑ move through the list;
// Ctrl+S goes to its search box.
func TestTemplatesKeys(t *testing.T) {
	e := setup(t)
	wantAll(t, "/templates", e.do(t, "dora", "GET", "/templates", nil, nil).Body.String(),
		`<input class="w360" name="title" placeholder="Title" aria-label="New template title" required aria-keyshortcuts="N">`,
		`<input type="search" id="tpl-q" class="w360" name="q"`, `<table class="table stable tpltable" data-arrows>`)
	wantAll(t, "keys.js", e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String(), "yarsSearchFocus('#fq, #tb-q, #tpl-q')")
}

// Notifications (History): m marks all read; ↓ ↑ move through the notices
// (Enter opens one, marking it read).
func TestNotificationsPageKeys(t *testing.T) {
	e := setup(t)
	wantAll(t, "/notifications", e.do(t, "alice", "GET", "/notifications", nil, nil).Body.String(),
		`<button class="btn secondary w152" disabled aria-keyshortcuts="M">Mark all read</button>`,
		`<table class="table stable notetable" data-arrows>`)
}

// Export: p Preview; Destinations: n New destination, ↓ ↑ through them,
// Enter edits.
func TestExportKeys(t *testing.T) {
	e := setup(t)
	wantAll(t, "export", e.do(t, "dora", "GET", "/e/acme/export", nil, nil).Body.String(),
		`formmethod="get" aria-keyshortcuts="P">Preview</button>`)
	// the page needs the export service (none in this setup): its template
	tplHas(t, "export_setup.html", `<a class="btn primary w160" href="/e/{{.Eng.ID}}/export/setup" aria-keyshortcuts="N">New destination</a>`,
		`<table class="table stable desttable flush" data-arrows>`,
		`<span class="btn save sm w96" aria-current="true" tabindex="0" data-nav>Editing</span>`,
		`<a class="btn ghost sm w96" href="/e/{{$.Eng.ID}}/export/setup?edit={{.ID}}" data-nav>Edit</a>`,
		`<button class="btn danger sm w112" form="dest-delete" data-confirm="Delete the destination {{.ID}}?">Delete</button>`)
}

// Admin › Rules and Webhooks: n a new one; ↓ ↑ through the rows; on the
// focused row d turns it on or off and e edits; deleting a webhook asks
// first, as do revoking a session or a token in Activity.
func TestAdminRulesWebhooksKeys(t *testing.T) {
	e := setup(t)
	e.rules(t, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n", nil)
	wantAll(t, "/admin/rules", e.do(t, "dora", "GET", "/admin/rules", nil, nil).Body.String(),
		`<a class="btn primary sm w128" href="/admin/rules?new=1" aria-keyshortcuts="N">New rule</a>`,
		`<table class="table ruletable" data-arrows="focus">`, `<tr data-rowkeys>`,
		`<a class="btn ghost sm w96" href="/admin/rules?edit=none" data-nav id="row-rule-none" aria-keyshortcuts="E">Edit</a>`,
		`<button class="toggle on" role="switch" aria-checked="true" aria-label="Enabled" aria-keyshortcuts="D"><span></span></button>`)
	tplHas(t, "admin.html", `<span class="btn save sm w96" aria-current="true" tabindex="0" data-nav id="row-rule-{{.ID}}">Editing</span>`,
		`<table class="table stable hooktable" data-arrows="focus">`,
		`<a href="/admin/webhooks?hook={{.ID}}" title="{{.URL}}" data-nav id="row-hook-{{.ID}}">{{.URL}}</a>`,
		`aria-label="Enabled" aria-keyshortcuts="D"><span></span></button>`,
		`<a class="btn secondary sm w96" href="/admin/webhooks?edit={{.ID}}&amp;hook={{.ID}}" aria-keyshortcuts="E">Edit</a>`,
		`<button class="btn danger sm w96" data-confirm="Delete the webhook to {{.URL}}?">Delete</button>`,
		`<input name="url" type="url" value="{{.Form.URL}}" placeholder="https://" required{{if not .Form.ID}} aria-keyshortcuts="N"{{end}}>`,
		`<button class="btn danger sm w96" data-confirm="Revoke {{.User}}'s session?">Revoke</button>`,
		`data-confirm="Revoke {{.User}}'s token {{.Name}}?">Revoke</button>`)
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	wantAll(t, "keys.js", js, "if (key === 'E') { if (yarsEdit() || yarsRowFire('E') || (!document.querySelector('[data-kpanel]') && yarsFire('E')) || yarsWrite(evt)) evt.preventDefault(); return; }")
}

// Engagement › Settings: a goes to "Add person"; removing someone asks first.
func TestEngSettingsKeys(t *testing.T) {
	e := setup(t)
	wantAll(t, "/e/acme/settings", e.do(t, "dora", "GET", "/e/acme/settings", nil, nil).Body.String(),
		`<select class="grow flush" name="user" aria-label="Add person" aria-keyshortcuts="A">`,
		`<button class="btn danger sm w96" aria-label="Remove alice" data-confirm="Remove alice from the team?">Remove</button>`)
}

// After review: text the server sent back counts as unsaved only while some
// is left (a refused empty reply left the board asking forever); x's row
// shows only where a row with a checkbox takes it; a table among other things
// (Settings' tokens, Admin's users, rules, webhooks) takes ↓ ↑ only from one
// of its rows and lets the page scroll past its ends; n is New webhook only
// when no webhook is being edited (it went to the edited one's URL).
func TestRestKeysReview(t *testing.T) {
	e := setup(t)
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	wantAll(t, "app.js", app, "function yarsChanged(i) {",
		"return i.hasAttribute('data-dirty') ? i.value.trim() !== '' : i.value !== i.defaultValue;",
		"return yarsChanged(i);",
		"return i === document.activeElement || (i.value !== undefined && i.defaultValue !== undefined && yarsChanged(i));")
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	wantAll(t, "keys.js", js, "var mixed = document.querySelector('[data-arrows=focus]');",
		"if (!row || !mixed.contains(row)) return false;",
		"if (i + d < 0 || i + d >= rows.length) return false;")
	if d := between(e.do(t, "alice", "GET", "/", nil, nil).Body.String(), `id="keys"`, "</dialog>"); !strings.Contains(d, `<div class="krow" data-keys-if="tr:has([data-nav]) input[type=checkbox]"><dt><kbd>x</kbd></dt><dd>Tick the row</dd></div>`) {
		t.Error("x's row shows where x ticks nothing")
	}
	tplHas(t, "settings.html", `<table class="table stable tokentable" data-arrows="focus">`)
	tplHas(t, "admin.html", `<table class="table stable usertable" data-arrows="focus">`, `<table class="table ruletable" data-arrows="focus">`,
		`<table class="table stable hooktable" data-arrows="focus">`,
		`placeholder="https://" required{{if not .Form.ID}} aria-keyshortcuts="N"{{end}}>`)
}

// The ? list names every key above, each where its control is.
func TestRestKeysListed(t *testing.T) {
	e := setup(t)
	d := between(e.do(t, "alice", "GET", "/", nil, nil).Body.String(), `id="keys"`, "</dialog>")
	wantAll(t, "the ? list", d,
		`<div class="krow" data-keys-if="a[aria-keyshortcuts~=N][href$='/board?new=1']"><dt><kbd>n</kbd></dt><dd>New lead</dd></div>`,
		`<div class="krow" data-keys-if="input[name=username][aria-keyshortcuts~=N]"><dt><kbd>n</kbd></dt><dd>Add user</dd></div>`,
		`<div class="krow" data-keys-if="a[aria-keyshortcuts~=N][href='/settings/tokens/new']"><dt><kbd>n</kbd></dt><dd>New token</dd></div>`,
		`<div class="krow" data-keys-if="input[name=title][aria-keyshortcuts~=N]"><dt><kbd>n</kbd></dt><dd>New template</dd></div>`,
		`<div class="krow" data-keys-if="a[aria-keyshortcuts~=N][href$='/export/setup']"><dt><kbd>n</kbd></dt><dd>New destination</dd></div>`,
		`<div class="krow" data-keys-if="a[aria-keyshortcuts~=N][href='/admin/rules?new=1']"><dt><kbd>n</kbd></dt><dd>New rule</dd></div>`,
		`<div class="krow" data-keys-if="input[name=url][aria-keyshortcuts~=N]"><dt><kbd>n</kbd></dt><dd>New webhook</dd></div>`,
		`<div class="krow" data-keys-for="P"><dt><kbd>p</kbd></dt><dd>Preview</dd></div>`,
		`<div class="krow" data-keys-if="select[aria-keyshortcuts~=A]"><dt><kbd>a</kbd></dt><dd>Add to the team</dd></div>`,
		`<div class="krow" data-keys-if="form[action$='/revoke'] [aria-keyshortcuts~=R]"><dt><kbd>r</kbd></dt><dd>Revoke the row's token</dd></div>`,
		`<div class="krow" data-keys-if="form[action$='/disabled'] [aria-keyshortcuts~=D], form[action$='/toggle'] [aria-keyshortcuts~=D]"><dt><kbd>d</kbd></dt><dd>Disable or enable the row</dd></div>`,
		`<div class="krow" data-keys-if="tr[data-rowkeys] [aria-keyshortcuts~=E]"><dt><kbd>e</kbd></dt><dd>Edit the row</dd></div>`,
		`<div class="krow" data-keys-if=".qacts [aria-keyshortcuts~=M], form[action='/notifications/read'] [aria-keyshortcuts~=M]"><dt><kbd>m</kbd></dt><dd>Mark all read</dd></div>`)
}
