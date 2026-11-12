package web

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// A section's open-thread count follows the chat without a reload: the
// panel listens for chat events, and its live refresh answers the new
// count once a thread on it opens (until then 204) (backlog, M4).
func TestSectionCountFollowsChat(t *testing.T) {
	e := setup(t)
	liveURL := func(b string) string {
		t.Helper()
		m := regexp.MustCompile(`<section class="panel" id="s-impact" data-kpanel hx-get="([^"]+)" hx-trigger="([^"]+)"`).FindStringSubmatch(b)
		if m == nil {
			t.Fatalf("no Impact panel:\n%s", b)
		}
		if !strings.Contains(m[2], "sse:chat") {
			t.Fatalf("the panel does not listen for chat: %s", m[2])
		}
		return html.UnescapeString(m[1])
	}
	before := liveURL(e.do(t, "alice", "GET", fpath, nil, nil).Body.String())
	if rec := e.do(t, "alice", "GET", before, nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("an unchanged panel: %d", rec.Code)
	}
	e.do(t, "bob", "POST", fpath+"/chat", url.Values{"text": {"impact is too low"}, "section": {"Impact"}}, nil)
	rec := e.do(t, "alice", "GET", before, nil, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `<span class="open-count">1</span>`) {
		t.Fatalf("after a thread on Impact: %d\n%s", rec.Code, rec.Body.String())
	}
	if rec := e.do(t, "alice", "GET", liveURL(rec.Body.String()), nil, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("the redrawn panel: %d", rec.Code)
	}
}
