package web

import (
	"strings"
	"testing"
)

// Settings › About gives every account the running version, the license
// and a link to the source of the build it is talking to (AGPL section
// 13). The address comes from the build, so a changed build names its own.
func TestSettingsAboutLinksTheSource(t *testing.T) {
	check := func(t *testing.T, e *env, user string) {
		e.srv.Version, e.srv.Source = "v9", "https://example.com/src"
		b := e.do(t, user, "GET", "/settings", nil, nil).Body.String()
		wantAll(t, "settings", b,
			`<a href="#about">About</a>`,
			`<section class="panel" id="about" data-kpanel data-kenter>`,
			`<div class="panelhead"><h2>About</h2><a class="btn ghost sm w112" href="https://example.com/src" target="_blank" rel="noopener">Source</a></div>`,
			`<div class="field"><span class="flabel">Version</span><span class="fvalue mono" title="v9">v9</span></div>`,
			`<div class="field"><span class="flabel">License</span><span class="fvalue">AGPL-3.0</span></div>`)
		// an unknown version shows a dash; without an address the link's
		// place stays, empty
		e.srv.Version, e.srv.Source = "", ""
		b = e.do(t, user, "GET", "/settings", nil, nil).Body.String()
		wantAll(t, "settings", b,
			`<div class="panelhead"><h2>About</h2><span class="slot w112"></span></div>`,
			`<span class="fvalue mono" title="—">—</span>`)
		// an address that is no web address is not a link target
		e.srv.Source = "javascript:alert(1)"
		if b = e.do(t, user, "GET", "/settings", nil, nil).Body.String(); strings.Contains(b, "javascript:alert") {
			t.Error("a script address reached the page")
		}
	}
	t.Run("standard", func(t *testing.T) { check(t, setup(t), "alice") }) // a pentester, no admin
	t.Run("simple", func(t *testing.T) { check(t, setupSimple(t), "anna") })
}
