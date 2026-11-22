package web

import (
	"net/url"
	"strings"
	"testing"
)

// Q23: the Checks strip's Message cell holds the whole message (cut with …
// on screen) and shows it whole on hover, then the rule; a dismissed row's
// too, with its quote.
func TestChecksLongMessageOnHover(t *testing.T) {
	e := setup(t)
	long := strings.TrimSpace(strings.Repeat("Use the word the client uses. ", 20))
	e.rules(t, "- id: title-word\n  target: title\n  regex_forbid: 'injection'\n  level: warning\n  message: "+long+"\n", nil)
	p := checksPanel(t, e.do(t, "alice", "GET", fpath+"/checks", nil, nil).Body.String())
	if want := `<td title="` + long + ` · title-word">` + long + `</td>`; !strings.Contains(p, want) {
		t.Fatalf("panel lacks %s:\n%s", want, p)
	}
	form := url.Values{"rule": {"title-word"}, "target": {"title"}, "quote": {"injection"}, "reason": {"agreed"}}
	rec := e.do(t, "alice", "POST", fpath+"/checks/dismiss", form, nil)
	if rec.Code != 200 {
		t.Fatalf("dismiss %d: %s", rec.Code, rec.Body.String())
	}
	if want := `<td title="` + long + ` · title-word · injection">` + long + `</td>`; !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("dismissed row lacks %s:\n%s", want, rec.Body.String())
	}
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	if !strings.Contains(css, ".checktable td { height: 48px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }") {
		t.Fatal("the strip's cells are not one line ending in …")
	}
}

// Q23: a live hint is one line ending in …, the message and quote whole on
// hover.
func TestHintLongMessageOneLine(t *testing.T) {
	e := setupSerial(t)
	long := strings.TrimSpace(strings.Repeat("No animals in the impact. ", 20))
	e.rules(t, "- id: zoo\n  target: section:Impact\n  regex_forbid: 'zebra'\n  message: "+long+"\n", nil)
	b := e.do(t, "alice", "POST", "/e/acme/preview?f="+fdir+"&s=Impact", url.Values{"body": {"a zebra here"}}, nil).Body.String()
	if want := `<span class="hint-text" title="` + long + ` — zebra">` + long + ` — <code>zebra</code></span>`; !strings.Contains(b, want) {
		t.Fatalf("hint lacks %s:\n%s", want, b)
	}
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	if !strings.Contains(css, ".hint-text { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }") {
		t.Fatal("a hint is not one line ending in …")
	}
}
