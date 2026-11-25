package web

import (
	"strconv"
	"strings"
	"testing"

	"yars/internal/db"
)

// Q24: a row key's control that posts its form (d, r, u, a) reloads the
// page; the same row is focused there again. The rows' controls the keys
// move to have stable ids; keys.js keeps the row once the form is sent (a
// cancelled confirm keeps nothing) for the next page only and a few seconds,
// and focuses it by id, else the row at its place in the same list.
func TestRowKeysKeepTheRow(t *testing.T) {
	e := setup(t)
	id, err := e.srv.Store.DB().CreateToken("alice", "h-abcd", "abcd", db.TokenSpec{Name: "laptop", Kind: db.TokenMCP, Scopes: []string{db.ScopeAll}})
	if err != nil {
		t.Fatal(err)
	}
	tok := "row-token-" + strconv.FormatInt(id, 10)
	if tag := tagOf(e.do(t, "alice", "GET", "/settings", nil, nil).Body.String(), tok); tag != `<span class="strong" title="laptop" tabindex="0" data-nav id="`+tok+`">` {
		t.Errorf("token row: %q", tag)
	}
	if tag := tagOf(e.do(t, "dora", "GET", "/admin/users", nil, nil).Body.String(), "row-user-alice"); tag != `<span class="strong" title="alice" tabindex="0" data-nav id="row-user-alice">` {
		t.Errorf("user row: %q", tag)
	}
	if tag := tagOf(e.do(t, "dora", "GET", "/", nil, nil).Body.String(), "row-eng-acme"); tag != `<a href="/e/acme" title="ACME Web" data-nav id="row-eng-acme">` {
		t.Errorf("engagement row: %q", tag)
	}
	e.rules(t, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n", nil)
	if tag := tagOf(e.do(t, "dora", "GET", "/admin/rules", nil, nil).Body.String(), "row-rule-none"); tag != `<a class="btn ghost sm w96" href="/admin/rules?edit=none" data-nav id="row-rule-none" aria-keyshortcuts="E">` {
		t.Errorf("rule row: %q", tag)
	}
	// the rule being edited keeps the id on its Editing mark
	if tag := tagOf(e.do(t, "dora", "GET", "/admin/rules?edit=none", nil, nil).Body.String(), "row-rule-none"); tag != `<span class="btn save sm w96" aria-current="true" tabindex="0" data-nav id="row-rule-none">` {
		t.Errorf("edited rule row: %q", tag)
	}
	tplHas(t, "admin.html", `<a href="/admin/webhooks?hook={{.ID}}" title="{{.URL}}" data-nav id="row-hook-{{.ID}}">{{.URL}}</a>`)
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	fire := js[strings.Index(js, "function yarsRowFire(key)"):]
	fire = fire[:strings.Index(fire, "\n}\n")]
	if k, p := strings.Index(fire, "yarsKeepRow(els[i], row);"), strings.Index(fire, "yarsPress(els[i]);"); k < 0 || k > p {
		t.Errorf("yarsRowFire does not keep the row before pressing:\n%s", fire)
	}
	wantAll(t, "keys.js", js,
		"var yarsRowKeep = 'yars-row-keep';",
		// a submit button of a plain form that posts: not an htmx one, not a link
		"var f = el.tagName === 'BUTTON' && el.type === 'submit' ? el.form : null;",
		"f.method === 'post' && !f.hasAttribute('hx-post')",
		// kept when that form is sent, not on the key
		"if (!k || evt.target !== k.form || evt.defaultPrevented) return;",
		"sessionStorage.setItem(yarsRowKeep, JSON.stringify({list: table.className, id: k.row.id, i: rows.indexOf(k.row), at: Date.now()}));",
		// a confirm answered Cancel sends nothing
		"if (evt.target.id === 'confirm' && evt.target.returnValue !== 'ok') yarsKeepNext = null;",
		// the next page only, a few seconds
		"sessionStorage.removeItem(yarsRowKeep);",
		"if (!k || !(Date.now() - k.at < 10000)) return;",
		"return x.className === k.list;",
		"if (rows.indexOf(el) < 0) el = rows[Math.min(Math.max(k.i, 0), rows.length - 1)];",
		"el.focus({preventScroll: true});",
		"el.scrollIntoView({block: 'nearest'});")
	// a confirm's OK sends the dialog's own form (method dialog) before the
	// row's: that submit neither keeps nor drops the row
	sub := between(js, "document.addEventListener('submit', function (evt) {", "\n});\n")
	if d, n := strings.Index(sub, "if (evt.target.method === 'dialog') return;"), strings.Index(sub, "yarsKeepNext = null;"); d < 0 || d > n {
		t.Errorf("the confirm's own submit drops the kept row:\n%s", sub)
	}
	// an address with #panel: the browser handles the fragment after
	// DOMContentLoaded (Chrome), jumping to the panel and taking the focus
	// off the row; the address loses it before the row is focused
	back := between(js, "var raw = sessionStorage.getItem(yarsRowKeep);", "\n});\n")
	if h, f := strings.Index(back, "if (location.hash) history.replaceState(history.state, '', location.pathname + location.search);"), strings.Index(back, "el.focus({preventScroll: true});"); h < 0 || h > f {
		t.Errorf("the fragment is not dropped before the row is focused:\n%s", back)
	}
}

// Q26: outside an engagement the picker shows the one kept from last time
// on a hidden option of its own, the real one unpicked, so picking it is a
// change and opens it (Enter on the shown one too); inside an engagement
// the picker is as before.
func TestPickerOpensKeptEngagement(t *testing.T) {
	e := setup(t)
	kept := map[string]string{"Cookie": "yars_eng=acme"}
	for _, p := range []string{"/inbox", "/settings", "/"} {
		sel := between(e.do(t, "alice", "GET", p, nil, kept).Body.String(), `<select name="eng"`, "</select>")
		wantAll(t, p+" picker", sel, `<option value="acme" selected hidden>ACME Web</option>`, `<option value="acme" >ACME Web</option>`)
		if n := strings.Count(sel, "selected"); n != 1 {
			t.Errorf("%s: %d options selected:\n%s", p, n, sel)
		}
		if strings.Contains(sel, `<option value="">Engagement</option>`) {
			t.Errorf("%s: the picker shows no engagement", p)
		}
	}
	sel := between(e.do(t, "alice", "GET", "/e/acme", nil, kept).Body.String(), `<select name="eng"`, "</select>")
	if !strings.Contains(sel, `<option value="acme" selected>ACME Web</option>`) || strings.Contains(sel, "hidden") {
		t.Errorf("inside the engagement:\n%s", sel)
	}
	sel = between(e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String(), `<select name="eng"`, "</select>")
	if !strings.Contains(sel, `<option value="">Engagement</option>`) || strings.Contains(sel, "hidden") || strings.Contains(sel, "selected") {
		t.Errorf("none kept:\n%s", sel)
	}
	// Back to a page: the browser would show the option picked to leave it
	// (its saved form state, or the page kept in its cache), so picking the
	// shown engagement would be no change again; the picker shows the
	// server's choice instead
	for _, p := range []string{"/inbox", "/e/acme"} {
		if b := e.do(t, "alice", "GET", p, nil, kept).Body.String(); !strings.Contains(b, `<select name="eng" data-choose autocomplete="off" aria-label="Engagement">`) {
			t.Errorf("%s: the picker's state is restored by the browser:\n%s", p, between(b, `<select name="eng"`, ">"))
		}
	}
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	wantAll(t, "app.js", app, "window.addEventListener('pageshow', function () { document.querySelectorAll('.engpick select').forEach(yarsSelectReset); });")
}

// Q28: a click on a list row outside its own controls selects it (focus on
// its data-nav, no scroll), so the row is tinted and its keys work; never
// while text is being selected; the team board's rows still open instead.
func TestRowClickSelects(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	wantAll(t, "keys.js", js,
		"if (!tr || tr.hasAttribute('data-rowclick') || !(tr.hasAttribute('data-rowkeys') || tr.closest('table[data-arrows]'))) return;",
		"var on = t.closest('a, button, input, select, textarea, label, summary, details, [tabindex], [contenteditable]');",
		"if (on && tr.contains(on)) return;",
		"if (s && !s.isCollapsed) return;",
		"if (nav && !nav.disabled) nav.focus({preventScroll: true});")
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	rule := ".table[data-arrows] tbody tr:not([data-rowclick]):has([data-nav]:focus) > td { background: var(--mark-bg); }"
	wantAll(t, "style.css", css, rule)
	if strings.Index(css, rule) < strings.Index(css, ".table.findings tbody tr.sel td") {
		t.Error("a ticked row's tint wins over the clicked row's")
	}
	// the board's own row click is untouched
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	wantAll(t, "app.js", app, "var row = evt.target.closest('[data-rowclick]');")
}

// Q33: Back (or Forward) on the team board with a reply or new lead typed
// asks Discard changes? first: htmx's popstate handler is wrapped once
// htmx set it; Discard runs it, Cancel keeps the board and puts its address
// back. Without unsaved text htmx restores as before.
func TestBoardBackAsks(t *testing.T) {
	e := setup(t)
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	wantAll(t, "app.js", app,
		"function yarsConfirm(text, ok, done, safe, no) {",
		"if (window.confirm(text)) done(); else if (no) no();",
		"d.onclose = function () { d.onclose = null; if (d.returnValue === 'ok') done(); else if (no) no(); };",
		"var yarsHere = location.href;",
		"['htmx:pushedIntoHistory', 'htmx:replacedInHistory', 'htmx:historyRestore'].forEach(function (n) {",
		"document.addEventListener(n, function () { yarsHere = location.href; });",
		"var restore = window.onpopstate;",
		"window.onpopstate = function (evt) {",
		"if (!evt.state || !evt.state.htmx || !b || !yarsDirty(b)) { restore.call(window, evt); yarsHere = location.href; return; }",
		"yarsConfirm('Discard changes?', 'Discard', function () { restore.call(window, evt); yarsHere = location.href; },",
		"false, function () { history.pushState({htmx: true}, '', was); });")
	// wrapped on DOMContentLoaded, after htmx's own (htmx loads first)
	if i := strings.Index(app, "var restore = window.onpopstate;"); i < 0 || !strings.Contains(app[strings.LastIndex(app[:i], "document.addEventListener("):i], "'DOMContentLoaded'") {
		t.Error("the popstate handler is not wrapped on DOMContentLoaded")
	}
	b := e.do(t, "alice", "GET", "/e/acme/board", nil, nil).Body.String()
	if h, a := strings.Index(b, "/htmx.min.js"), strings.Index(b, "/app.js"); h < 0 || a < h {
		t.Error("app.js loads before htmx")
	}
}
