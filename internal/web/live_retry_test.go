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
	exp := jsFunc(t, app, "function yarsExpired(own)", "\n}\n")
	if strings.Contains(exp, "Date.now() - ") || !strings.Contains(exp, "if (own ? shown : yarsExpiredSaid) return;") {
		t.Errorf("the toast repeats while the session stays expired:\n%s", exp)
	}
	// the draft and the editor's state are still written at every 401
	if !strings.Contains(exp, "yarsDraftWrite(form, true);") || !strings.Contains(exp, "Session expired · not saved") {
		t.Errorf("yarsExpired keeps no draft:\n%s", exp)
	}
	// an answered request ends the expiry, so a later one is said again
	if !strings.Contains(app, "if (x && x.status >= 200 && x.status < 400) yarsExpiredSaid = false;") {
		t.Error("nothing ends an expiry: a second one would not be said")
	}
}

// 5.7: the once-rule is for the 401s nobody asked for (a poll, a presence
// beat). A request the user sent (Send, Edit, Check, a filter, an upload)
// that gets 401 says "Session expired" again, unless that toast still shows:
// the first one may have come and gone in a tab nobody looked at. Pins of
// the script's text.
func TestSessionExpiredSaidForOwnRequest(t *testing.T) {
	e := setup(t)
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	// the toast is handed back, so the page knows whether it still shows
	if toast := jsFunc(t, app, "function yarsToast(text, err)", "\n}\n"); !strings.Contains(toast, "return t;") {
		t.Errorf("yarsToast hands back no toast:\n%s", toast)
	}
	exp := jsFunc(t, app, "function yarsExpired(own)", "\n}\n")
	for _, want := range []string{
		"var shown = yarsExpiredToast && yarsExpiredToast.isConnected;",
		"if (own ? shown : yarsExpiredSaid) return;",
		"yarsExpiredToast = yarsToast('Session expired', true);",
	} {
		if !strings.Contains(exp, want) {
			t.Errorf("yarsExpired lacks %s:\n%s", want, exp)
		}
	}
	// an htmx request is the user's own unless a live event sent it
	herr := jsFunc(t, app, "document.addEventListener('htmx:responseError', function (evt) {", "\n});")
	for _, want := range []string{
		"evt.detail.requestConfig && evt.detail.requestConfig.triggeringEvent",
		"indexOf('sse:') === 0",
		"if (xhr && xhr.status === 401) { yarsExpired(!live); return; }",
	} {
		if !strings.Contains(herr, want) {
			t.Errorf("the 401 of an htmx request: no %s:\n%s", want, herr)
		}
	}
	// an upload is the user's own; the presence beat is not
	if up := jsFunc(t, app, "function yarsUpload(", "\n}\n"); !strings.Contains(up, "if (r.status === 401) { yarsExpired(true); return false; }") {
		t.Error("the 401 of an upload is not said as the user's own request")
	}
	if !strings.Contains(app, "if (r.status === 401) yarsExpired(); else if (r.ok) yarsExpiredSaid = false;") {
		t.Error("the 401 of a presence beat is not under the once-rule")
	}
}
