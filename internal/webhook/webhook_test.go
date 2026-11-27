package webhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/secret"
	"github.com/abno525/yars/internal/store"
)

type got struct {
	sig, event, id string
	body           []byte
	ts, eventID    string
}

// receiver is a webhook endpoint answering the given statuses in turn
// (the last one repeats).
type receiver struct {
	mu       sync.Mutex
	statuses []int
	reqs     []got
}

func (rc *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	rc.mu.Lock()
	rc.reqs = append(rc.reqs, got{r.Header.Get("X-YARS-Signature"), r.Header.Get("X-YARS-Event"), r.Header.Get("X-YARS-Delivery"), b,
		r.Header.Get("X-YARS-Timestamp"), r.Header.Get("X-YARS-Event-ID")})
	st := rc.statuses[min(len(rc.reqs)-1, len(rc.statuses)-1)]
	rc.mu.Unlock()
	w.WriteHeader(st)
}

func (rc *receiver) count() int { rc.mu.Lock(); defer rc.mu.Unlock(); return len(rc.reqs) }

func newService(t *testing.T) (*Service, *db.DB, *time.Time) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "y.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	box, _ := secret.New(make([]byte, 32))
	now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	s := &Service{DB: d, Secrets: func() (Sealer, error) { return box, nil }, Now: func() time.Time { return now },
		BaseURL: func() string { return "https://yars.example.com" }}
	return s, d, &now
}

func returned() store.Event {
	return store.Event{Kind: store.EventStatus, At: time.Date(2026, 11, 5, 14, 12, 9, 0, time.UTC), Actor: "rev1", Eng: "demo",
		Dir: "F-001-sql-injection-in-login", Fid: "F-001", Title: "SQL injection in login", Severity: "critical", Author: "pen1",
		Action: "return", From: "verification", To: "draft", Reason: "add a PoC"}
}

func TestSignedDelivery(t *testing.T) {
	s, d, _ := newService(t)
	rc := &receiver{statuses: []int{204}}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	id, sec, err := s.Create(srv.URL+"/hook", []string{store.EventStatus}, "dora")
	if err != nil || id == 0 || !strings.HasPrefix(sec, "whsec_") {
		t.Fatal(id, sec, err)
	}
	h, _, _ := d.WebhookByID(id)
	if strings.Contains(h.SecretEnc, sec) || h.Last4 != sec[len(sec)-4:] {
		t.Fatalf("secret stored as %+v", h)
	}
	s.Handle(returned())
	s.Handle(store.Event{Kind: store.EventChat, Eng: "demo"}) // not subscribed
	if n, err := s.RunDue(); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if rc.count() != 1 {
		t.Fatalf("requests %d", rc.count())
	}
	r := rc.reqs[0]
	if r.sig != mac(sec, r.ts+"."+string(r.body)) || r.event != store.EventStatus || r.id == "" {
		t.Fatalf("headers %+v", r)
	}
	var p map[string]any
	json.Unmarshal(r.body, &p)
	f, _ := p["finding"].(map[string]any)
	if p["event"] != "finding.status_changed" || p["actor"] != "rev1" || p["engagement"] != "demo" || p["from"] != "verification" ||
		p["to"] != "draft" || p["reason"] != "add a PoC" || p["at"] != "2026-11-05T14:12:09Z" ||
		p["url"] != "https://yars.example.com/e/demo/f/001" || f["id"] != "F-001" || f["author"] != "pen1" || f["severity"] != "critical" {
		t.Fatalf("payload %s", r.body)
	}
	last, _ := d.LastDeliveries()
	if last[id].State != db.DeliveryOK || last[id].Status != 204 {
		t.Fatalf("%+v", last[id])
	}
	// nothing left to send
	if n, _ := s.RunDue(); n != 0 {
		t.Fatalf("sent again %d", n)
	}
}

// finding.updated can be taken and carries what changed.
func TestUpdatedPayload(t *testing.T) {
	s, _, _ := newService(t)
	if err := ValidEvents([]string{store.EventUpdated}); err != nil {
		t.Fatal(err)
	}
	b := s.Payload(store.Event{Kind: store.EventUpdated, Eng: "demo", Dir: "F-001-x", Fid: "F-001", Actor: "pen1", Changed: []string{"Title", "Impact"}})
	var p struct {
		Event   string   `json:"event"`
		Changed []string `json:"changed"`
	}
	if err := json.Unmarshal(b, &p); err != nil || p.Event != "finding.updated" || strings.Join(p.Changed, ",") != "Title,Impact" {
		t.Fatalf("%s %v", b, err)
	}
}

// A failing endpoint is retried with exponential backoff, at most 6 tries.
func TestRetryBackoff(t *testing.T) {
	s, d, now := newService(t)
	rc := &receiver{statuses: []int{500, 502, 204}}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	id, _, _ := s.Create(srv.URL, Events, "dora")
	s.Handle(returned())
	s.RunDue()
	dl, _ := d.Deliveries(id, 1)
	if dl[0].State != db.DeliveryPending || dl[0].Attempts != 1 || dl[0].Status != 500 || dl[0].NextAt != "2026-11-05T12:00:10Z" {
		t.Fatalf("after 1 %+v", dl[0])
	}
	// not due yet
	*now = now.Add(5 * time.Second)
	if n, _ := s.RunDue(); n != 0 {
		t.Fatal("retried early")
	}
	*now = now.Add(5 * time.Second)
	s.RunDue()
	dl, _ = d.Deliveries(id, 1)
	if dl[0].Attempts != 2 || dl[0].NextAt != "2026-11-05T12:00:30Z" { // 10 s, then 20 s
		t.Fatalf("after 2 %+v", dl[0])
	}
	*now = now.Add(20 * time.Second)
	s.RunDue()
	if dl, _ = d.Deliveries(id, 1); dl[0].State != db.DeliveryOK || dl[0].Attempts != 3 {
		t.Fatalf("after 3 %+v", dl[0])
	}

	// always failing: gives up after 6 tries
	bad := &receiver{statuses: []int{500}}
	srv2 := httptest.NewServer(bad)
	defer srv2.Close()
	id2, _, _ := s.Create(srv2.URL, Events, "dora")
	s.Handle(store.Event{Kind: store.EventCreated, Eng: "demo", Fid: "F-002", Dir: "F-002-x"})
	for range 20 {
		*now = now.Add(time.Hour)
		s.RunDue()
	}
	dl, _ = d.Deliveries(id2, 1)
	if dl[0].State != db.DeliveryFailed || dl[0].Attempts != MaxTries || bad.count() != MaxTries {
		t.Fatalf("gave up %+v after %d", dl[0], bad.count())
	}
	// Redeliver sends it again
	if err := s.Redeliver(dl[0].ID); err != nil {
		t.Fatal(err)
	}
	bad.mu.Lock()
	bad.statuses = []int{200}
	bad.mu.Unlock()
	s.RunDue()
	if l, _ := d.Deliveries(id2, 1); l[0].State != db.DeliveryOK || bad.count() != MaxTries+1 {
		t.Fatalf("redelivered %+v", l[0])
	}
}

// Disabled webhooks get nothing; Run sends as soon as an event is queued.
func TestDisabledAndWorker(t *testing.T) {
	s, d, _ := newService(t)
	rc := &receiver{statuses: []int{200}}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	id, _, _ := s.Create(srv.URL, Events, "dora")
	d.SetWebhookEnabled(id, false)
	s.Handle(returned())
	if l, _ := d.Deliveries(id, 10); len(l) != 0 {
		t.Fatal("queued for a disabled hook")
	}
	d.SetWebhookEnabled(id, true)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { s.Run(stop); close(done) }()
	s.Handle(returned())
	deadline := time.Now().Add(5 * time.Second)
	for rc.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	<-done
	if rc.count() != 1 {
		t.Fatalf("worker sent %d", rc.count())
	}
}

// Turning a webhook off stops deliveries already queued (and their retries).
func TestDisabledStopsQueued(t *testing.T) {
	s, d, _ := newService(t)
	rc := &receiver{statuses: []int{200}}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	id, _, _ := s.Create(srv.URL, Events, "dora")
	s.Handle(returned())
	d.SetWebhookEnabled(id, false)
	s.RunDue()
	if rc.count() != 0 {
		t.Fatalf("sent %d to a disabled hook", rc.count())
	}
	l, _ := d.Deliveries(id, 1)
	if l[0].State != db.DeliveryFailed || l[0].Error != "webhook disabled" {
		t.Fatalf("%+v", l[0])
	}
}

// A try that cannot be recorded ends the pass with the error instead of
// sending the same delivery again and again.
func TestUnrecordedAttemptStopsPass(t *testing.T) {
	s, d, _ := newService(t)
	rc := &receiver{statuses: []int{204}}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	s.Create(srv.URL, Events, "dora")
	s.Handle(returned())
	if _, err := d.Exec("CREATE TRIGGER boom BEFORE UPDATE ON webhook_deliveries BEGIN SELECT RAISE(ABORT, 'disk full'); END"); err != nil {
		t.Fatal(err)
	}
	type res struct {
		n   int
		err error
	}
	done := make(chan res, 1)
	go func() { n, err := s.RunDue(); done <- res{n, err} }()
	select {
	case r := <-done:
		if r.err == nil || !strings.Contains(r.err.Error(), "disk full") || r.n != 1 || rc.count() != 1 {
			t.Fatalf("n %d err %v sent %d", r.n, r.err, rc.count())
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("pass never ended; sent %d times", rc.count())
	}
}

func TestValidURL(t *testing.T) {
	for _, u := range []string{"https://hooks.example/a", "http://10.0.0.5:8080/x"} {
		if err := ValidURL(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{"", "ftp://x", "hooks.example", "https://", "javascript:alert(1)"} {
		if ValidURL(u) == nil {
			t.Errorf("%s accepted", u)
		}
	}
	if err := ValidEvents([]string{"chat.posted", "nope"}); err == nil {
		t.Error("unknown event accepted")
	}
	if err := ValidEvents(nil); err == nil {
		t.Error("no events accepted")
	}
}
