package web

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/events"
)

// ended reads the stream until it closes and returns its lines; a stream
// still open after two seconds fails the test.
func (s *sseStream) ended(t *testing.T, why string) []string {
	t.Helper()
	var got []string
	deadline := time.After(2 * time.Second)
	for {
		select {
		case l, ok := <-s.lines:
			if !ok {
				return got
			}
			got = append(got, l)
		case <-deadline:
			t.Fatalf("the stream is still open %s", why)
		}
	}
}

// An open event stream is checked again at every heartbeat: it ends once
// the session is gone (logout), the account is disabled, or the account left
// the engagement's team.
func TestSSEEndsWhenAccessEnds(t *testing.T) {
	for _, c := range []struct {
		name string
		end  func(t *testing.T, e *env)
	}{
		{"after logout", func(t *testing.T, e *env) {
			if rec := e.do(t, "alice", "POST", "/logout", nil, nil); rec.Code != http.StatusSeeOther {
				t.Fatalf("logout: code %d", rec.Code)
			}
		}},
		{"after the account is disabled", func(t *testing.T, e *env) {
			if err := e.srv.Store.DB().SetDisabled("alice", true); err != nil {
				t.Fatal(err)
			}
		}},
		{"after the account must set a new password", func(t *testing.T, e *env) {
			if _, err := e.srv.Store.DB().Exec("UPDATE users SET must_change = 1 WHERE username = 'alice'"); err != nil {
				t.Fatal(err)
			}
		}},
		{"after the account left the team", func(t *testing.T, e *env) {
			if err := e.srv.Store.RemoveMember("acme", "alice", wDora); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := setup(t)
			e.srv.heartbeat = 50 * time.Millisecond
			ts := e.liveServer(t)
			s := e.openSSE(t, ts, "eng=acme", nil)
			s.waitFor(t, ": ping") // checked once, and still open
			c.end(t, e)
			s.ended(t, c.name)
		})
	}
}

// Between two heartbeats no event of an engagement reaches an account that
// left its team: the team is read for every event, and the stream ends.
func TestSSENoEventAfterTeamRemoval(t *testing.T) {
	for _, q := range []string{"eng=acme", "eng=acme&f=F-001", ""} {
		t.Run("stream "+q, func(t *testing.T) {
			e := setup(t)
			ts := e.liveServer(t)
			s := e.openSSE(t, ts, q, nil)
			s.waitFor(t, "id: ")
			if err := e.srv.Store.RemoveMember("acme", "alice", wDora); err != nil {
				t.Fatal(err)
			}
			e.srv.Events.Publish(events.Event{Eng: "acme", Fid: "F-001", Kind: events.Chat})
			if q == "" {
				// a stream of every engagement stays open, without that event
				e.srv.Events.Publish(events.Event{Kind: events.Push})
				if l := s.waitFor(t, "event: "); l != "event: push" {
					t.Fatalf("got %q after the removal", l)
				}
				return
			}
			for _, l := range s.ended(t, "after an event of an engagement the account left") {
				if strings.HasPrefix(l, "event: ") {
					t.Fatalf("got %q after the removal", l)
				}
			}
		})
	}
}

// An account holds at most maxStreams event streams at once; one that ends
// makes room for the next.
func TestSSEStreamsPerUser(t *testing.T) {
	e := setup(t)
	e.srv.maxStreams = 2
	ts := e.liveServer(t)
	open := func(user string) *http.Response {
		req, _ := http.NewRequest("GET", ts.URL+"/events?eng=acme", nil)
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks[user]})
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	first := e.openSSE(t, ts, "eng=acme", nil)
	e.openSSE(t, ts, "eng=acme", nil).waitFor(t, "id: ")
	first.waitFor(t, "id: ")
	if resp := open("alice"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("stream %d of alice: code %d", e.srv.maxStreams+1, resp.StatusCode)
	}
	// the cap is per account
	if resp := open("bob"); resp.StatusCode != http.StatusOK {
		t.Fatalf("bob's first stream: code %d", resp.StatusCode)
	}
	first.resp.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for {
		resp := open("alice")
		if resp.StatusCode == http.StatusOK {
			return
		}
		resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatalf("no room after a stream closed: code %d", resp.StatusCode)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The check at each heartbeat is no use of the session: an open tab does not
// keep a session from going idle.
func TestSSEHeartbeatDoesNotRefreshSession(t *testing.T) {
	e := setup(t)
	e.srv.heartbeat = 20 * time.Millisecond
	ts := e.liveServer(t)
	s := e.openSSE(t, ts, "eng=acme", nil)
	s.waitFor(t, "id: ")
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	d := e.srv.Store.DB()
	if _, err := d.Exec("UPDATE sessions SET last_seen = ? WHERE username = 'alice'", old); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		s.waitFor(t, ": ping")
	}
	var seen string
	if err := d.QueryRow("SELECT last_seen FROM sessions WHERE username = 'alice'").Scan(&seen); err != nil || seen != old {
		t.Fatalf("last_seen %q %v, want %q: the heartbeat counted as a use", seen, err, old)
	}
}
