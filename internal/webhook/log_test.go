package webhook

import (
	"log/slog"
	"net/http/httptest"
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
		*now = now.Add(time.Hour)
		s.RunDue()
	}
	gone := out.With("webhook delivery given up")
	if len(out.With("webhook delivery failed; it is tried again")) != MaxTries-1 || len(gone) != 1 || gone[0].Level != slog.LevelWarn ||
		gone[0].Str("try") != "6" || gone[0].Str("status") != "500" {
		t.Fatalf("log:\n%s", out.Text())
	}
	if text := out.Text(); strings.Contains(text, "zq") || strings.Contains(text, "127.0.0.1") || strings.Contains(text, "Internal Server Error") {
		t.Fatalf("the log holds the address or text:\n%s", text)
	}
}
