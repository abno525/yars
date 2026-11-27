package web

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The vendored htmx is one release's dist/htmx.min.js, byte for byte: its
// version and its SHA-256 are written here, so the file is never edited by
// hand and an upgrade changes these two lines, NOTICE and the licence file
// together.
const (
	htmxVersion = "2.0.11"
	htmxSHA256  = "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717"
)

func TestHtmxVersion(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "GET", "/static/htmx.min.js", nil, nil)
	js := rec.Body.Bytes()
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	m := regexp.MustCompile(`version:"([0-9]+\.[0-9]+\.[0-9]+)"`).FindSubmatch(js)
	if m == nil || string(m[1]) != htmxVersion {
		t.Errorf("the served htmx names version %q, want %s", m, htmxVersion)
	}
	if sum := sha256.Sum256(js); hex.EncodeToString(sum[:]) != htmxSHA256 {
		t.Errorf("htmx.min.js is not the release file: SHA-256 %x", sum)
	}
	name := "htmx " + htmxVersion + " (htmx.min.js)"
	notice, err := os.ReadFile("../../NOTICE")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(notice), "\n"+name+"\n") {
		t.Errorf("NOTICE does not name %s", name)
	}
	lic, err := staticFS.ReadFile("static/htmx.LICENSE.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(lic), name+", https://github.com/bigskysoftware/htmx\n") {
		t.Errorf("htmx.LICENSE.txt does not start with %s", name)
	}
}

// What the pages and scripts lean on inside htmx is still in the file: the
// configuration keys layout.html sets, the events and their details app.js,
// keys.js and sse.js read, the attributes the templates use, and the
// popstate handler app.js wraps (set as window.onpopstate, not added as a
// listener). A pin of names only: no behaviour is run.
func TestHtmxInternals(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/htmx.min.js", nil, nil).Body.String()
	for _, w := range []string{
		// layout.html's htmx-config
		"allowEval", "includeIndicatorStyles", "historyCacheSize", "refreshOnHistoryMiss", "responseHandling",
		// Back to a pushed address loads the page again, never a fragment
		".location.reload(true)", "window.onpopstate=function(",
		// htmx:confirm's detail (app.js)
		"htmx:confirm", "issueRequest", "question", "triggeringEvent",
		// swaps and requests
		"htmx:beforeSwap", "shouldSwap", "requestConfig", "htmx:beforeRequest", "htmx:afterRequest", "htmx:afterSwap", "htmx:afterSettle",
		"htmx:responseError", "htmx:sendError", "htmx:load",
		"htmx:pushedIntoHistory", "htmx:replacedInHistory", "htmx:historyRestore",
		// attributes of the templates
		"hx-sync", "hx-disabled-elt", "hx-swap-oob", "hx-push-url", "hx-include", "hx-confirm",
	} {
		if !strings.Contains(js, w) {
			t.Errorf("htmx.min.js lacks %s", w)
		}
	}
}
