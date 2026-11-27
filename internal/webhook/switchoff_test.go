package webhook

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/store"
)

// giveUp queues one event and runs the clock until its delivery is given up
// or delivered.
func giveUp(t *testing.T, s *Service, now *time.Time) {
	t.Helper()
	s.Handle(returned())
	for range 40 {
		if _, err := s.RunDue(); err != nil {
			t.Fatal(err)
		}
		*now = now.Add(2 * time.Hour)
	}
}

// A webhook whose deliveries are given up five times in a row is switched
// off: nothing more is queued for it.
func TestDeadWebhookIsSwitchedOff(t *testing.T) {
	s, d, now := newService(t)
	lg, out := logs.NewRecorder()
	s.Logger = lg
	var told []db.Webhook
	s.SwitchedOff = func(h db.Webhook) { told = append(told, h) }
	rc := &receiver{statuses: []int{500}}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	id, _, err := s.Create(srv.URL+"/zqpath7f3kq", []string{store.EventStatus}, "dora")
	if err != nil {
		t.Fatal(err)
	}
	for i := range DisableAfter {
		if h, _, _ := d.WebhookByID(id); !h.Enabled || h.Failures != i {
			t.Fatalf("before delivery %d: %+v", i+1, h)
		}
		giveUp(t, s, now)
	}
	h, _, _ := d.WebhookByID(id)
	if h.Enabled || h.Failures != DisableAfter {
		t.Fatalf("still enabled after %d deliveries given up: %+v", DisableAfter, h)
	}
	before := rc.count()
	s.Handle(returned())
	if n, _ := s.RunDue(); n != 0 || rc.count() != before {
		t.Fatalf("a switched-off webhook was sent to: %d tries", n)
	}
	// said once, in three places: the notice, the audit log, the service log
	if len(told) != 1 || told[0].ID != id {
		t.Fatalf("told %+v", told)
	}
	log, _ := d.AuditLog(10)
	if len(log) != 1 || log[0].Actor != "yars" || log[0].Action != "webhook.disable" || log[0].Target != srv.URL+"/zqpath7f3kq" ||
		log[0].Detail != "5 deliveries given up in a row" {
		t.Fatalf("audit %+v", log)
	}
	off := out.With("webhook switched off after failed deliveries")
	if len(off) != 1 || off[0].Attrs["webhook"] != id || off[0].Str("failures") != "5" {
		t.Fatalf("log:\n%s", out.Text())
	}
	if strings.Contains(out.Text(), "zq") || strings.Contains(out.Text(), "127.0.0.1") {
		t.Fatalf("the log holds the address:\n%s", out.Text())
	}

	// switched on again: the count starts again, one failure switches nothing
	if err := d.SetWebhookEnabled(id, true); err != nil {
		t.Fatal(err)
	}
	giveUp(t, s, now)
	if h, _, _ := d.WebhookByID(id); !h.Enabled || h.Failures != 1 || len(told) != 1 {
		t.Fatalf("after Enable and one failure: %+v", h)
	}
	// another address starts the count again too
	if err := d.UpdateWebhook(id, srv.URL+"/v2", []string{store.EventStatus}, true); err != nil {
		t.Fatal(err)
	}
	if h, _, _ := d.WebhookByID(id); h.Failures != 0 {
		t.Fatalf("after a new URL: %+v", h)
	}
}

// Only deliveries given up in a row count: one that arrives starts the count
// again. A delivery dropped because the webhook is off counts for nothing.
func TestDeliveredResetsTheCount(t *testing.T) {
	s, d, now := newService(t)
	rc := &receiver{statuses: []int{500}}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	id, _, _ := s.Create(srv.URL, []string{store.EventStatus}, "dora")
	set := func(st int) { rc.mu.Lock(); rc.statuses = []int{st}; rc.mu.Unlock() }
	for range DisableAfter - 1 {
		giveUp(t, s, now)
	}
	set(204)
	giveUp(t, s, now)
	if h, _, _ := d.WebhookByID(id); !h.Enabled || h.Failures != 0 {
		t.Fatalf("after a delivery that arrived: %+v", h)
	}
	set(500)
	for range DisableAfter - 1 {
		giveUp(t, s, now)
	}
	if h, _, _ := d.WebhookByID(id); !h.Enabled || h.Failures != DisableAfter-1 {
		t.Fatalf("%d failures, a success, %d failures: %+v", DisableAfter-1, DisableAfter-1, h)
	}
	// turned off by hand with deliveries queued: they are dropped, not counted
	s.Handle(returned())
	s.Handle(returned())
	d.SetWebhookEnabled(id, false)
	s.RunDue()
	if h, _, _ := d.WebhookByID(id); h.Failures != DisableAfter-1 {
		t.Fatalf("dropped deliveries were counted: %+v", h)
	}
}

// The waits between tries: short first, an hour at most, and a delivery is
// tried for hours before it is given up.
func TestRetrySchedule(t *testing.T) {
	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second, 160 * time.Second, 320 * time.Second,
		640 * time.Second, 1280 * time.Second, 2560 * time.Second, time.Hour, time.Hour}
	if len(want) != MaxTries-1 {
		t.Fatalf("%d waits for %d tries", len(want), MaxTries)
	}
	var total time.Duration
	for i, w := range want {
		if got := wait(i + 1); got != w {
			t.Fatalf("wait after try %d: %v, want %v", i+1, got, w)
		}
		total += w
	}
	if total < 3*time.Hour {
		t.Fatalf("given up after %v", total)
	}
	if wait(1000) != MaxBackoff {
		t.Fatalf("wait(1000) = %v", wait(1000))
	}

	// the stored next try follows it
	s, d, now := newService(t)
	rc := &receiver{statuses: []int{500}}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	id, _, _ := s.Create(srv.URL, []string{store.EventStatus}, "dora")
	s.Handle(returned())
	for i, w := range want {
		s.RunDue()
		dl, _ := d.Deliveries(id, 1)
		if next := now.Add(w).Format(time.RFC3339); dl[0].Attempts != i+1 || dl[0].NextAt != next || dl[0].State != db.DeliveryPending {
			t.Fatalf("after try %d: %+v, want the next at %s", i+1, dl[0], next)
		}
		*now = now.Add(w)
	}
	s.RunDue()
	if dl, _ := d.Deliveries(id, 1); dl[0].State != db.DeliveryFailed || dl[0].Attempts != MaxTries {
		t.Fatalf("after the last try: %+v", dl[0])
	}
}

// A try that got no HTTP answer says why in one fixed word, in the delivery's
// row and in the log; neither holds the address.
func TestNoAnswerSaysWhy(t *testing.T) {
	cases := []struct {
		name, want string
		url        func(t *testing.T) string
		client     *http.Client
	}{
		{"closed port", "connection refused", func(t *testing.T) string {
			srv := httptest.NewServer(&receiver{statuses: []int{204}})
			srv.Close()
			return srv.URL + "/zqpath7f3kq"
		}, nil},
		{"slow receiver", "timeout", func(t *testing.T) string {
			release := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
			t.Cleanup(func() { close(release); srv.Close() })
			return srv.URL + "/zqpath7f3kq"
		}, &http.Client{Timeout: 50 * time.Millisecond}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, d, _ := newService(t)
			lg, out := logs.NewRecorder()
			s.Logger, s.Client = lg, c.client
			id, _, err := s.Create(c.url(t), []string{store.EventStatus}, "dora")
			if err != nil {
				t.Fatal(err)
			}
			s.Handle(returned())
			if _, err := s.RunDue(); err != nil {
				t.Fatal(err)
			}
			dl, _ := d.Deliveries(id, 1)
			if dl[0].Error != c.want || dl[0].State != db.DeliveryPending {
				t.Fatalf("row error %q, want %q", dl[0].Error, c.want)
			}
			recs := out.Records()
			if len(recs) != 1 || recs[0].Str("err") != c.want {
				t.Fatalf("log:\n%s", out.Text())
			}
			if text := out.Text() + dl[0].Error; strings.Contains(text, "zq") || strings.Contains(text, "127.0.0.1") {
				t.Fatalf("the address is in the log or the row:\n%s", text)
			}
		})
	}
}
