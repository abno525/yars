package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// 5.5: Go to's list names the query it answers, as the field sent it, so
// Enter can tell a list of an earlier query from the one for what is typed.
func TestGoToStampsItsQuery(t *testing.T) {
	e := setup(t)
	get := func(q string) string {
		t.Helper()
		rec := e.do(t, "alice", "GET", "/go/search?q="+url.QueryEscape(q), nil, map[string]string{"HX-Request": "true"})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %d", q, rec.Code)
		}
		return rec.Body.String()
	}
	if b := get("injection"); !strings.Contains(b, `<div class="gh" data-q="injection">`) || !strings.Contains(b, `<a class="res sel" href="/e/acme/f/001"`) {
		t.Fatalf("a list without its query:\n%s", b)
	}
	// as sent: capitals and spaces are the field's
	if b := get(" F-001 "); !strings.Contains(b, `data-q=" F-001 "`) || !strings.Contains(b, `href="/e/acme/f/001"`) {
		t.Fatalf("the query is not echoed as sent:\n%s", b)
	}
	// no match: still the answer to that query
	if b := get("zzzz"); !strings.Contains(b, `data-q="zzzz"`) {
		t.Fatalf("an empty list without its query:\n%s", b)
	}
	if b := get(`"><b>`); !strings.Contains(b, `data-q="&#34;&gt;&lt;b&gt;"`) || strings.Contains(b, "<b>") {
		t.Fatalf("the query is not escaped:\n%s", b)
	}
	// nothing typed: the empty list carries no query
	if b := get(""); strings.Contains(b, "data-q") {
		t.Fatalf("empty query:\n%s", b)
	}

	// the script (a pin of its text; no test runs it): Enter opens the
	// picked row only when the list is the answer to the field's text, and
	// not while an input method composes
	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	i := strings.Index(js, "} else if (evt.key === 'Enter') {\n    if (evt.isComposing) return;")
	if i < 0 {
		t.Fatal("Go to's Enter does not wait for a composition")
	}
	fn := js[i : i+strings.Index(js[i:], "\n});")]
	if !strings.Contains(fn, "getAttribute('data-q') === inp.value") {
		t.Fatalf("Enter opens a row of an earlier query:\n%s", fn)
	}
}
