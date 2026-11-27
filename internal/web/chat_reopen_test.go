package web

import (
	"net/url"
	"strings"
	"testing"
)

// A reply sent from a page that still showed the thread open, after someone
// else resolved it, opens the thread again: it is listed open, with its
// reply box and Resolve, and it counts.
func TestReplyToResolvedThreadReopensIt(t *testing.T) {
	e := setup(t)
	hx := map[string]string{"HX-Request": "true"}
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"Impact overstated?"}, "section": {"Impact"}}, hx)
	msgs, _ := e.srv.Store.DB().Messages("acme", "F-001")
	id := msgs[0].ID
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"resolves": {id}}, hx)
	if b := e.do(t, "alice", "GET", fpath, nil, nil).Body.String(); !strings.Contains(b, `class="thread resolved" id="t-`+id+`"`) {
		t.Fatal("the thread is not resolved")
	}
	rec := e.do(t, "alice", "POST", fpath+"/chat", url.Values{"text": {"No: see the PoC"}, "reply": {id}}, hx)
	list := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(list, `<div class="thread" id="t-`+id+`"`) || !strings.Contains(list, `id="resolve-`+id+`"`) ||
		strings.Contains(list, `class="thread resolved"`) {
		t.Fatalf("after the reply %d:\n%s", rec.Code, list)
	}
	b := e.do(t, "bob", "GET", fpath, nil, nil).Body.String()
	if !strings.Contains(b, `<span class="threads">1 open</span>`) {
		t.Fatal("the reopened thread is not counted")
	}
}
