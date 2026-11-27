package web

import (
	"strings"
	"testing"
)

// 5.7: a page that fell back to polling tries the stream again at each poll
// tick and when the tab is shown; once a stream opens the polling stops and
// the page catches up itself (a new stream sends no Last-Event-ID, so the
// server sends no resync). "Session expired" is said once per expiry, not
// at every poll. No test runs the scripts: these are pins of their text.
func TestSSERetriesFromPolling(t *testing.T) {
	e := setup(t)
	js := e.do(t, "alice", "GET", "/static/sse.js", nil, nil).Body.String()
	poll := jsFunc(t, js, "function startPolling()", "\n  }\n")
	if !strings.Contains(poll, "if (!es) connect();") || !strings.Contains(poll, "document.hidden") || !strings.Contains(poll, "fire('poll')") {
		t.Errorf("the poll tick does not try the stream again:\n%s", poll)
	}
	conn := jsFunc(t, js, "function connect()", "\n  }\n")
	open := jsFunc(t, conn, "s.onopen = function () {", "\n    };")
	for _, want := range []string{"if (es !== s) return;", "if (pollTimer)", "stopPolling();", "fire('resync');"} {
		if !strings.Contains(open, want) {
			t.Errorf("onopen lacks %s:\n%s", want, open)
		}
	}
	if stop := jsFunc(t, js, "function stopPolling()", "\n  }\n"); !strings.Contains(stop, "clearInterval(pollTimer)") || !strings.Contains(stop, "pollTimer = null") {
		t.Errorf("stopPolling: %s", stop)
	}
	// a tab shown again while polling: a poll now and the stream tried again;
	// a hidden tab still holds no stream (TestSSEClosedInHiddenTabs)
	vis := jsFunc(t, js, "function onVisibility()", "\n  }\n")
	if i := strings.Index(vis, "} else if (pollTimer) {"); i < 0 || !strings.Contains(vis[i:], "if (!es) connect();") {
		t.Errorf("a shown tab keeps polling without trying the stream:\n%s", vis)
	}
	if strings.Contains(js, "connect(url)") {
		t.Error("connect takes no argument")
	}

	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	exp := jsFunc(t, app, "function yarsExpired()", "\n}\n")
	if strings.Contains(exp, "Date.now() - ") || !strings.Contains(exp, "if (!yarsExpiredSaid) { yarsExpiredSaid = true; yarsToast('Session expired', true); }") {
		t.Errorf("the toast repeats while the session stays expired:\n%s", exp)
	}
	// the draft and the editor's state are still written at every 401
	if !strings.Contains(exp, "localStorage.setItem(yarsDraftKey(form)") || !strings.Contains(exp, "Session expired · not saved") {
		t.Errorf("yarsExpired keeps no draft:\n%s", exp)
	}
	// an answered request ends the expiry, so a later one is said again
	if !strings.Contains(app, "if (x && x.status >= 200 && x.status < 400) yarsExpiredSaid = false;") {
		t.Error("nothing ends an expiry: a second one would not be said")
	}
}
