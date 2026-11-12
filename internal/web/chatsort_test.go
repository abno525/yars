package web

import (
	"strings"
	"testing"
)

// The Chat column's first click shows the findings with the most open
// threads first; the next click turns the order round. The other columns
// start ascending (backlog, M4).
func TestChatColumnStartsDescending(t *testing.T) {
	e := setup(t)
	b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String()
	if !strings.Contains(b, `href="/e/acme?desc=1&amp;sort=chat"`) {
		t.Fatal("the Chat column does not start descending")
	}
	if !strings.Contains(b, `href="/e/acme?sort=title"`) {
		t.Fatal("the Title column does not start ascending")
	}
	if b := e.do(t, "alice", "GET", "/e/acme?desc=1&sort=chat", nil, nil).Body.String(); !strings.Contains(b, `href="/e/acme?sort=chat"`) {
		t.Fatal("the second click on Chat does not turn the order round")
	}
}
