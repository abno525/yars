package web

import (
	"bytes"
	"log"
	"net/url"
	"os"
	"strings"
	"testing"
)

// A failed login is one line of the service log, with the name as typed
// (quoted, cut) and the address the request came from; never the password.
// A good login writes none. The lockout is a line too. An X-Forwarded-For
// header is shown, labelled, only when the server runs behind a declared
// proxy (--https).
func TestFailedLoginsReachTheServiceLog(t *testing.T) {
	e := setupSerial(t)
	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	login := func(name, pw string, hdr map[string]string) string {
		t.Helper()
		out.Reset()
		e.do(t, "", "POST", "/login", url.Values{"username": {name}, "password": {pw}}, hdr)
		return out.String()
	}
	fwd := map[string]string{"X-Forwarded-For": "203.0.113.9\nfake line"}
	got := login("alice", "wrong-secret", fwd)
	if got == "" || strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "login failed: user \"alice\" from 192.0.2.1:1234\n") {
		t.Fatalf("log of a failed login: %q", got)
	}
	if strings.Contains(got, "wrong-secret") || strings.Contains(got, "203.0.113.9") {
		t.Fatalf("the password or a client's header in the log: %q", got)
	}
	if got := login("alice", "pw", nil); got != "" {
		t.Fatalf("a good login logged %q", got)
	}
	// the name is the client's text: one line, cut
	if got := login("mal\nlory fake line", "x", nil); strings.Count(got, "\n") != 1 || !strings.Contains(got, `user "mal\nlory fake line" from`) {
		t.Fatalf("a name with a line break: %q", got)
	}
	if got := login(strings.Repeat("a", 5000), "x", nil); len(got) > 300 || !strings.Contains(got, strings.Repeat("a", 64)+`…" from`) {
		t.Fatalf("a long name: %d bytes: %.200q", len(got), got)
	}
	// behind a declared proxy the forwarded address is shown, as the client's
	// or the proxy's text
	e.srv.Auth.Secure = true
	if got := login("alice", "wrong-secret", fwd); strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, `login failed: user "alice" from 192.0.2.1:1234 forwarded-for "203.0.113.9\nfake line"`+"\n") {
		t.Fatalf("with --https: %q", got)
	}
	// the failure that starts the lockout logs it, once
	out.Reset()
	for range 6 {
		e.do(t, "", "POST", "/login", url.Values{"username": {"bob"}, "password": {"bad"}}, nil)
	}
	if got := out.String(); strings.Count(got, `login locked: user "bob" until `) != 1 || strings.Count(got, `login failed: user "bob"`) != 6 {
		t.Fatalf("lockout log:\n%s", got)
	}
}
