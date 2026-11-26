package web

import (
	"bytes"
	"log/slog"
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/logs"
)

// A failed login is one line of the service log, with the name as typed
// (cut) and the address the request came from; never the password. A good
// login writes none. The lockout is a line too. An X-Forwarded-For header is
// shown, labelled, only when the server runs behind a declared proxy
// (--https).
func TestFailedLoginsReachTheServiceLog(t *testing.T) {
	e := setupSerial(t)
	login := func(name, pw string, hdr map[string]string) []logs.Record {
		t.Helper()
		e.log.Reset()
		e.do(t, "", "POST", "/login", url.Values{"username": {name}, "password": {pw}}, hdr)
		return e.log.With("login failed")
	}
	fwd := map[string]string{"X-Forwarded-For": "203.0.113.9\nfake line"}
	got := login("alice", "wrong-secret", fwd)
	if len(got) != 1 || got[0].Str("user") != "alice" || got[0].Str("remote") != "192.0.2.1:1234" || got[0].Level < slog.LevelInfo {
		t.Fatalf("log of a failed login: %s", e.log.Text())
	}
	if all := e.log.Text(); strings.Contains(all, "wrong-secret") || strings.Contains(all, "203.0.113.9") || got[0].Has("forwarded_for") {
		t.Fatalf("the password or a client's header in the log: %s", all)
	}
	if got := login("alice", "pw", nil); len(got) != 0 || strings.Contains(e.log.Text(), "login failed") {
		t.Fatalf("a good login logged %s", e.log.Text())
	}
	// the name is the client's text: one line, cut
	if got := login("mal\nlory fake line", "x", nil); len(got) != 1 || got[0].Str("user") != "mal\nlory fake line" {
		t.Fatalf("a name with a line break: %s", e.log.Text())
	}
	if got := login(strings.Repeat("a", 5000), "x", nil); len(got) != 1 || got[0].Str("user") != strings.Repeat("a", 64)+"…" {
		t.Fatalf("a long name: %.300s", e.log.Text())
	}
	// behind a declared proxy the forwarded address is shown, as the client's
	// or the proxy's text
	e.srv.Auth.Secure = true
	if got := login("alice", "wrong-secret", fwd); len(got) != 1 || got[0].Str("remote") != "192.0.2.1:1234" || got[0].Str("forwarded_for") != "203.0.113.9\nfake line" {
		t.Fatalf("with --https: %s", e.log.Text())
	}
	// the failure that starts the lockout logs it, once
	e.log.Reset()
	for range 6 {
		e.do(t, "", "POST", "/login", url.Values{"username": {"bob"}, "password": {"bad"}}, nil)
	}
	locked, failed := e.log.With("login locked"), e.log.With("login failed")
	if len(locked) != 1 || locked[0].Str("user") != "bob" || !locked[0].Has("until") || len(failed) != 6 || failed[5].Str("user") != "bob" {
		t.Fatalf("lockout log:\n%s", e.log.Text())
	}
}

// On stderr a failed login is one line in both formats, whatever the name
// holds: a line break in a client's text never starts a second line.
func TestFailedLoginIsOneLine(t *testing.T) {
	for _, format := range []string{logs.Text, logs.JSON} {
		e := setupSerial(t)
		var out bytes.Buffer
		e.srv.Auth.Logger = logs.New(&out, format, slog.LevelInfo)
		e.do(t, "", "POST", "/login", url.Values{"username": {"mal\nlory fake line"}, "password": {"x"}}, map[string]string{"X-Forwarded-For": "1.2.3.4\nfake"})
		if got := out.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, `mal\nlory fake line`) || !strings.Contains(got, "login failed") {
			t.Errorf("%s: %q", format, got)
		}
	}
}
