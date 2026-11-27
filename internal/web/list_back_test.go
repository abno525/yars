package web

import (
	"strings"
	"testing"
)

// 5.6: the links that lead back to an engagement's findings list are marked
// with the engagement (data-list), and the script puts the list's last
// filter, sort and search back on them. The server's href stays the bare
// list, for a browser without the script. The remembering itself is the
// script's: no test runs it, its text is pinned.
func TestListLinksAreMarked(t *testing.T) {
	e := setup(t)
	const crumb = `<nav class="crumbs"><a href="/e/acme" data-list="acme">`
	for _, p := range []string{fpath, fpath + "/history", "/e/acme/findings/new", "/e/acme/export"} {
		b := e.do(t, "alice", "GET", p, nil, nil).Body.String()
		if !strings.Contains(b, crumb) {
			t.Errorf("%s: the crumb is not marked:\n%s", p, between(b, `<nav class="crumbs">`, "</nav>"))
		}
		// f and the Findings link of the top bar
		if !strings.Contains(b, `<a data-list="acme" class="on" href="/e/acme" aria-keyshortcuts="F">Findings</a>`) {
			t.Errorf("%s: the Findings link is not marked:\n%s", p, between(b, `<nav class="nav">`, "</nav>"))
		}
	}
	// the Findings tab of the other tabs; no other tab is marked
	for _, p := range []string{"/e/acme/overview", "/e/acme/report", "/e/acme/settings", "/e/acme"} {
		tabs := between(e.do(t, "dora", "GET", p, nil, nil).Body.String(), `<nav class="etabs"`, "</nav>")
		if !strings.Contains(tabs, `<a data-list="acme" class="etab`) || strings.Count(tabs, "data-list") != 1 {
			t.Errorf("%s: tabs:\n%s", p, tabs)
		}
	}
	// no engagement open and none kept: nothing to go back to
	if nav := between(e.do(t, "alice", "GET", "/settings", nil, nil).Body.String(), `<nav class="nav">`, "</nav>"); strings.Contains(nav, `href="/"`) && strings.Contains(nav, "data-list") {
		t.Errorf("the Findings link without an engagement is marked:\n%s", nav)
	}

	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	keep := jsFunc(t, js, "function yarsListKeep()", "\n}\n")
	if on := jsFunc(t, js, "function yarsOnList()", "\n}\n"); !strings.Contains(on, "getElementById('findings')") || !strings.Contains(on, "location.pathname") {
		t.Errorf("yarsOnList: %s", on)
	}
	for _, want := range []string{"yarsOnList()", "location.search", "delete('offset')", "delete('keep')", "sessionStorage.setItem(yarsListKey("} {
		if !strings.Contains(keep, want) {
			t.Errorf("yarsListKeep lacks %s:\n%s", want, keep)
		}
	}
	links := jsFunc(t, js, "function yarsListLinks(root)", "\n}\n")
	// the link's own path and a stored query only: never a stored path
	for _, want := range []string{"[data-list]", "a.pathname + ", "charAt(0) !== '?'", "yarsOnList()"} {
		if !strings.Contains(links, want) {
			t.Errorf("yarsListLinks lacks %s:\n%s", want, links)
		}
	}
	// per account, and Log out forgets them
	if key := jsFunc(t, js, "function yarsListKey(eng)", "\n"); !strings.Contains(key, "yarsUser()") {
		t.Errorf("the kept list is not per account: %s", key)
	}
	if !strings.Contains(js, "yarsForget('yars-list:' + yarsUser() + ':', sessionStorage)") {
		t.Error("Log out keeps the list queries")
	}
}
