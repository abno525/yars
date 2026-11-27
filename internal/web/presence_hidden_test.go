package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// 5.3: an editor in a hidden tab still counts as open. Browsers run a hidden
// tab's timers once a minute at most, so the server waits longer than one
// such beat, and the script beats whether the tab shows or not.
func TestPresenceHiddenTab(t *testing.T) {
	e := setup(t)
	beat := func() {
		t.Helper()
		if rec := e.do(t, "alice", "POST", fpath+"/s/Impact/presence", url.Values{}, nil); rec.Code != http.StatusNoContent {
			t.Fatalf("heartbeat %d", rec.Code)
		}
	}
	shown := func() bool {
		return strings.Contains(e.do(t, "bob", "GET", fpath+"/s/Impact/presence", nil, nil).Body.String(), "alice")
	}
	beat()
	defer func() { e.srv.presence.now = time.Now }()
	// a hidden tab's beat comes after a minute and some seconds
	e.srv.presence.now = func() time.Time { return time.Now().Add(75 * time.Second) }
	if !shown() {
		t.Fatal("an editor is forgotten before a hidden tab's next beat")
	}
	// one missed beat of a hidden tab is still not the end
	e.srv.presence.now = func() time.Time { return time.Now().Add(2*time.Minute + 15*time.Second) }
	if !shown() {
		t.Fatal("an editor is forgotten after one missed beat of a hidden tab")
	}
	e.srv.presence.now = func() time.Time { return time.Now().Add(presenceTTL + time.Second) }
	if shown() {
		t.Fatal("an editor without a beat is shown for good")
	}

	js := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	fn := jsFunc(t, js, "// Presence: an open editor", "\n}, 20000);")
	if strings.Contains(fn, "document.hidden") || !strings.Contains(fn, "form[data-presence]") {
		t.Fatalf("the beat stops in a hidden tab:\n%s", fn)
	}
}
