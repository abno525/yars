package web

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// A save on Settings comes back to /settings with no #panel: the fragment
// made the browser scroll to that panel and outline it (a theme change
// jumped to Preferences). keys.js puts the page back where it was: the
// scroll, the selected panel, focus on the same control. Only a new token
// goes to its panel, for the secret shown once.
func TestSettingsSavesStayInPlace(t *testing.T) {
	e := setup(t)
	for _, c := range []struct {
		path string
		form url.Values
	}{
		{"/settings/prefs", url.Values{"theme": {"dark"}}},
		{"/settings/account", url.Values{"email": {"alice@example.com"}}},
		{"/settings/notifications", url.Values{}},
	} {
		rec := e.do(t, "alice", "POST", c.path, c.form, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/settings" {
			t.Errorf("%s: %d %q", c.path, rec.Code, rec.Header().Get("Location"))
		}
	}
	src, err := os.ReadFile("settings.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(src), `"/settings#`); n != 1 || !strings.Contains(string(src), `http.Redirect(w, r, "/settings#tokens", http.StatusSeeOther)
}

func (s *Server) tokenRevoke(`) {
		t.Errorf("settings.go sends %d saves to a panel; only a new token should go to #tokens", n)
	}
	b := e.do(t, "alice", "GET", "/settings", nil, nil).Body.String()
	if !strings.Contains(b, `<div class="smain" data-keep-place>`) {
		t.Error("Settings' panels are not marked to keep the place")
	}
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	wantAll(t, "keys.js", js,
		"var yarsPlaceKeep = 'yars-place-keep';",
		"!f.closest('[data-keep-place]')",
		// a checkbox is told by its value too (every Notifications box is "n")
		"var value = name && (a.type === 'checkbox' || a.type === 'radio') ? a.value : '';",
		"sessionStorage.setItem(yarsPlaceKeep, JSON.stringify({y: window.scrollY, sel: yarsSel, form: f.id, name: name, value: value, at: Date.now()}));",
		"if (k.value) els = els.filter(function (x) { return x.type === 'radio' || x.value === k.value; });",
		"sessionStorage.removeItem(yarsPlaceKeep);",
		"if (!k || !(Date.now() - k.at < 10000) || !document.querySelector('[data-keep-place]')) return;",
		// smooth scrolling (html) would animate the way back
		"window.scrollTo({top: k.y, behavior: 'instant'});",
		// with the shortcuts off nothing is selected (its outline would stay)
		"if (p && p.hasAttribute('data-kpanel') && !yarsKeysOff()) yarsSelect(p, false);",
		// a row a key kept (Revoke) keeps the focus
		"if (a && a !== document.body) return;",
		"el.focus({preventScroll: true});")
}

// Settings' keys are the finding page's: ↓ ↑ j k select a panel (a click
// too), Enter goes into it (its checked choice, else its first row, field
// or button), Enter on a choice or checkbox saves its form, Esc goes back
// out to the panel. The ? list shows them as a Settings group, not the
// finding page's or the lists'.
func TestSettingsKeysLikeTheFindingPage(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/settings", nil, nil).Body.String()
	for _, id := range []string{"account", "prefs", "password", "notifications"} {
		if !strings.Contains(b, `<form class="panel" id="`+id+`" data-kpanel data-kenter method="post"`) {
			t.Errorf("panel %s is not a key panel", id)
		}
	}
	for _, id := range []string{"tokens", "connections"} {
		if !strings.Contains(b, `<section class="panel" id="`+id+`" data-kpanel data-kenter>`) {
			t.Errorf("panel %s is not a key panel", id)
		}
	}
	js := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	enter := between(js, "function yarsEnter() {", "\n}\n")
	if i, a := strings.Index(enter, "if (p.hasAttribute('data-kenter'))"), strings.Index(enter, "var a = document.activeElement;"); i < 0 || i > a {
		t.Errorf("yarsEnter does not go into a Settings panel first:\n%s", enter)
	}
	// any focused control (a Save, a nav link, a field) keeps its Enter: the
	// panel is gone into only with nothing focused
	if !strings.Contains(enter, "if (cur && cur !== document.body && cur !== p) return false;") {
		t.Errorf("yarsEnter takes Enter from a focused control:\n%s", enter)
	}
	wantAll(t, "keys.js", js,
		"function yarsInto(p) {",
		"p.querySelector('[data-nav]') || p.querySelector('input:not([type=hidden]), select, textarea') || p.querySelector('button, a.btn')",
		"function yarsChoiceSave(t) {",
		"t.matches('input[type=radio], input[type=checkbox]') || !t.closest('[data-kenter]')",
		"if (key === 'Enter' && !yarsKeysOff() && !evt.repeat && !evt.isComposing && yarsChoiceSave(evt.target)) { evt.preventDefault(); return; }",
		"if (sel && sel.hasAttribute('data-kenter') && a && a !== document.body && sel.contains(a)) { a.blur(); return; }",
		`show('[data-keys-group="finding"]', document.querySelector('[data-kpanel]') && !kenter);`,
		`show('[data-keys-group="settings"]', kenter);`,
		`show('[data-keys-group="lists"]', document.querySelector('[data-nav]') && !kenter);`)
	// Enter on a choice is handled before a field keeps the keys out
	disp := js[strings.Index(js, "document.addEventListener('keydown', function (evt) {\n  var key = yarsKeyOf(evt);"):]
	if c, f := strings.Index(disp, "yarsChoiceSave(evt.target)"), strings.Index(disp, "(yarsTyping(evt.target) && !yarsPick(evt.target))"); c < 0 || c > f {
		t.Error("Enter on a choice comes after the field check")
	}
	wantAll(t, "the ? list", b,
		`<section class="kgroup" data-keys-group="settings"><h3 class="gh">Settings</h3>`,
		`<div class="krow"><dt><kbd>Enter</kbd></dt><dd>Go into the panel, then save</dd></div>`,
		`<div class="krow"><dt><kbd>Esc</kbd></dt><dd>Back to the panel</dd></div>`)
}
