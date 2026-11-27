package webhook

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/store"
)

// Each try of a delivery writes one line: info when it arrived, warn when it
// failed and is tried again, warn when it is given up. The line names the
// webhook and the delivery by their IDs, the event, the HTTP status and the
// try; never the address (it can hold a secret) or the payload.
func TestDeliveryIsLogged(t *testing.T) {
	s, _, now := newService(t)
	lg, out := logs.NewRecorder()
	s.Logger = lg
	rc := &receiver{statuses: []int{500, 204}}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	id, _, err := s.Create(srv.URL+"/zqpath7f3kq?key=zqquery7f3kq", []string{store.EventStatus}, "dora")
	if err != nil {
		t.Fatal(err)
	}
	e := returned()
	e.Title, e.Reason = "zqtitle7f3kq", "zqreason7f3kq"
	s.Handle(e)
	s.RunDue()
	retry := out.With("webhook delivery failed; it is tried again")
	if len(retry) != 1 || len(out.Records()) != 1 {
		t.Fatalf("log:\n%s", out.Text())
	}
	r := retry[0]
	if r.Level != slog.LevelWarn || r.Attrs["webhook"] != id || !r.Has("delivery") || r.Str("event") != store.EventStatus ||
		r.Str("status") != "500" || r.Str("try") != "1" || !r.Has("ms") {
		t.Fatalf("line: %s", r)
	}
	*now = now.Add(time.Minute)
	s.RunDue()
	sent := out.With("webhook delivered")
	if len(sent) != 1 || sent[0].Level != slog.LevelInfo || sent[0].Attrs["webhook"] != id || sent[0].Str("status") != "204" || sent[0].Str("try") != "2" {
		t.Fatalf("log:\n%s", out.Text())
	}

	// always failing: the last try is given up
	out.Reset()
	bad := httptest.NewServer(&receiver{statuses: []int{500}})
	defer bad.Close()
	if _, _, err := s.Create(bad.URL, []string{store.EventCreated}, "dora"); err != nil {
		t.Fatal(err)
	}
	s.Handle(store.Event{Kind: store.EventCreated, Eng: "demo", Fid: "F-002", Dir: "F-002-zqslug7f3kq"})
	for range MaxTries + 2 {
		*now = now.Add(2 * time.Hour)
		s.RunDue()
	}
	gone := out.With("webhook delivery given up")
	if len(out.With("webhook delivery failed; it is tried again")) != MaxTries-1 || len(gone) != 1 || gone[0].Level != slog.LevelWarn ||
		gone[0].Str("try") != strconv.Itoa(MaxTries) || gone[0].Str("status") != "500" {
		t.Fatalf("log:\n%s", out.Text())
	}
	if text := out.Text(); strings.Contains(text, "zq") || strings.Contains(text, "127.0.0.1") || strings.Contains(text, "Internal Server Error") {
		t.Fatalf("the log holds the address or text:\n%s", text)
	}
}

// A try without an HTTP answer says why in err, as one fixed word: never the
// address, the other host of a redirect or the words of the error. A try
// that got an answer has its status and no err.
func TestDeliveryFailureSaysWhy(t *testing.T) {
	one := func(t *testing.T, s *Service, out *logs.Recorder, msg, why string) logs.Record {
		t.Helper()
		out.Reset()
		if _, err := s.RunDue(); err != nil {
			t.Fatal(err)
		}
		recs := out.Records()
		if len(recs) != 1 || recs[0].Msg != msg || recs[0].Str("err") != why || recs[0].Str("status") != "0" {
			t.Fatalf("want one line %q with err=%q:\n%s", msg, why, out.Text())
		}
		if text := out.Text(); strings.Contains(text, "zq") || strings.Contains(text, "127.0.0.1") {
			t.Fatalf("the log holds the address or text:\n%s", text)
		}
		return recs[0]
	}
	const again = "webhook delivery failed; it is tried again"

	t.Run("connection refused", func(t *testing.T) {
		s, _, _ := newService(t)
		lg, out := logs.NewRecorder()
		s.Logger = lg
		srv := httptest.NewServer(&receiver{statuses: []int{204}})
		if _, _, err := s.Create(srv.URL+"/zqpath7f3kq", []string{store.EventStatus}, "dora"); err != nil {
			t.Fatal(err)
		}
		srv.Close() // nothing listens there now
		s.Handle(returned())
		if r := one(t, s, out, again, "connection refused"); r.Level != slog.LevelWarn {
			t.Fatalf("line: %s", r)
		}
	})

	t.Run("redirect refused", func(t *testing.T) {
		s, _, _ := newService(t)
		lg, out := logs.NewRecorder()
		s.Logger = lg
		other := httptest.NewServer(&receiver{statuses: []int{204}})
		defer other.Close()
		first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/zqcollect7f3kq", http.StatusTemporaryRedirect)
		}))
		defer first.Close()
		if _, _, err := s.Create(first.URL+"/hook", []string{store.EventStatus}, "dora"); err != nil {
			t.Fatal(err)
		}
		s.Handle(returned())
		one(t, s, out, again, "redirect refused")
	})

	t.Run("secret", func(t *testing.T) {
		s, _, now := newService(t)
		lg, out := logs.NewRecorder()
		s.Logger = lg
		srv := httptest.NewServer(&receiver{statuses: []int{204}})
		defer srv.Close()
		if _, _, err := s.Create(srv.URL, []string{store.EventStatus}, "dora"); err != nil {
			t.Fatal(err)
		}
		s.Handle(returned())
		box, _ := s.Secrets()
		// the key file cannot be read
		s.Secrets = func() (Sealer, error) { return nil, errors.New("open /zqkey7f3kq: permission denied") }
		one(t, s, out, again, "secret")
		// the key is another one: the stored secret does not open
		s.Secrets = func() (Sealer, error) { return wrongKey{box}, nil }
		*now = now.Add(time.Hour)
		one(t, s, out, again, "secret")
	})

	t.Run("an answer has no err", func(t *testing.T) {
		s, _, _ := newService(t)
		lg, out := logs.NewRecorder()
		s.Logger = lg
		srv := httptest.NewServer(&receiver{statuses: []int{500}})
		defer srv.Close()
		if _, _, err := s.Create(srv.URL, []string{store.EventStatus}, "dora"); err != nil {
			t.Fatal(err)
		}
		s.Handle(returned())
		s.RunDue()
		recs := out.With(again)
		if len(recs) != 1 || recs[0].Has("err") || recs[0].Str("status") != "500" {
			t.Fatalf("log:\n%s", out.Text())
		}
	})
}

// A delivery whose webhook was turned off is no fault: its line is info, so
// a queue of them does not push warnings out of the System panel's list.
func TestDisabledDeliveryIsInfo(t *testing.T) {
	s, d, _ := newService(t)
	lg, out := logs.NewRecorder()
	s.Logger = lg
	srv := httptest.NewServer(&receiver{statuses: []int{204}})
	defer srv.Close()
	id, _, err := s.Create(srv.URL+"/zqpath7f3kq", []string{store.EventStatus}, "dora")
	if err != nil {
		t.Fatal(err)
	}
	for range 30 {
		s.Handle(returned())
	}
	d.SetWebhookEnabled(id, false)
	if n, err := s.RunDue(); err != nil || n != 30 {
		t.Fatal(n, err)
	}
	recs := out.Records()
	if len(recs) != 30 {
		t.Fatalf("log:\n%s", out.Text())
	}
	for _, r := range recs {
		if r.Level != slog.LevelInfo || r.Msg != "webhook delivery dropped" || r.Str("err") != "disabled" || r.Str("status") != "0" ||
			r.Attrs["webhook"] != id || !r.Has("delivery") || r.Str("try") != "1" {
			t.Fatalf("line: %s", r)
		}
	}
	if strings.Contains(out.Text(), "zq") || strings.Contains(out.Text(), "127.0.0.1") {
		t.Fatalf("the log holds the address:\n%s", out.Text())
	}
}

// wrongKey is a Sealer that opens nothing.
type wrongKey struct{ Sealer }

func (wrongKey) Decrypt(string) (string, error) {
	return "", errors.New("cipher: message authentication failed zqcipher7f3kq")
}
