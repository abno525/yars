package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The findings board refreshes itself on the engagement's events (a push,
// an edit, a state change elsewhere) with its filters kept, and brings the
// progress panel along; it holds off while rows are picked or more loaded.
func TestFindingsBoardLive(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme?sort=title", nil, nil).Body.String()
	head := between(b, `<div id="findings"`, ">")
	for _, want := range []string{`data-sse-url="/events?eng=acme"`, `hx-get="/e/acme?sort=title"`, "sse:content", "sse:workflow", "sse:resync", "yarsListIdle()", "data-sse"} {
		if !strings.Contains(head, want) {
			t.Errorf("findings head lacks %q: %s", want, head)
		}
	}
	rec := e.do(t, "alice", "GET", "/e/acme?sort=title", nil, map[string]string{"HX-Request": "true", "HX-Trigger": "findings"})
	if body := rec.Body.String(); !strings.Contains(body, `id="findings"`) || !strings.Contains(body, `id="engbars" hx-swap-oob="true"`) {
		t.Fatalf("live refresh:\n%s", body)
	}
	if body := e.do(t, "alice", "GET", "/e/acme?sort=title", nil, map[string]string{"HX-Request": "true"}).Body.String(); strings.Contains(body, "hx-swap-oob") {
		t.Fatal("a filter click sends the bars out of band")
	}
	if js := e.do(t, "alice", "GET", staticPrefix()+"/app.js", nil, nil).Body.String(); !strings.Contains(js, "yarsListIdle") {
		t.Fatal("app.js lacks yarsListIdle")
	}
}

// A title made only of bidi controls is empty once cleaned: the form says
// so (400 with the form), not a bare error from the store.
func TestNewFindingBidiOnlyTitle(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"\u202e\u2066"}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Title is required.") {
		t.Fatalf("%d:\n%s", rec.Code, rec.Body)
	}
}

// A finding ID (F-001, as MCP, chat and reports name it) opens the finding
// like its number or folder does.
func TestFindingByID(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/e/acme/f/F-001", "/e/acme/f/F-1", "/e/acme/f/F-001/history"} {
		rec := e.do(t, "alice", "GET", p, nil, nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "SQL injection") {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	if rec := e.do(t, "alice", "GET", "/e/acme/f/F-099", nil, nil); rec.Code != 404 {
		t.Errorf("unknown ID: %d", rec.Code)
	}
}
