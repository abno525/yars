package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/abno525/yars/internal/store"
)

// mac is the signature a receiver computes over signed.
func mac(secret, signed string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(signed))
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

// bodyID is the id field of a delivery's body.
func bodyID(t *testing.T, body []byte) string {
	t.Helper()
	var p struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	return p.ID
}

// A delivery says when it was sent, and the signature covers that time with
// the body: a body caught on the way cannot be sent again later. The time is
// that of the try, so a late retry is still fresh; the event's ID is the same
// on every try.
func TestSignatureCoversTheTime(t *testing.T) {
	s, _, now := newService(t)
	rc := &receiver{statuses: []int{500, 204}}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	_, sec, err := s.Create(srv.URL, []string{store.EventStatus}, "dora")
	if err != nil {
		t.Fatal(err)
	}
	s.Handle(returned())
	s.RunDue()
	if rc.count() != 1 {
		t.Fatalf("requests %d", rc.count())
	}
	r := rc.reqs[0]
	if want := strconv.FormatInt(now.Unix(), 10); r.ts != want {
		t.Fatalf("X-YARS-Timestamp %q, want %q", r.ts, want)
	}
	if r.sig != mac(sec, r.ts+"."+string(r.body)) {
		t.Fatalf("the signature is not over timestamp.body: %+v", r)
	}
	if r.sig == mac(sec, string(r.body)) {
		t.Fatal("the signature is over the body alone")
	}
	if r.sig != Sign(sec, now.Unix(), r.body) {
		t.Fatal("Sign differs from what was sent")
	}
	if r.eventID == "" || r.eventID != bodyID(t, r.body) {
		t.Fatalf("X-YARS-Event-ID %q, body id %q", r.eventID, bodyID(t, r.body))
	}

	// the retry, an hour late: its own time, the same event
	*now = now.Add(time.Hour)
	s.RunDue()
	if rc.count() != 2 {
		t.Fatalf("requests %d", rc.count())
	}
	r2 := rc.reqs[1]
	if want := strconv.FormatInt(now.Unix(), 10); r2.ts != want || r2.ts == r.ts {
		t.Fatalf("the retry's timestamp %q, want %q", r2.ts, want)
	}
	if r2.sig != mac(sec, r2.ts+"."+string(r2.body)) || r2.eventID != r.eventID || r2.id != r.id {
		t.Fatalf("retry %+v after %+v", r2, r)
	}
}

// The event's ID is the same for every webhook that takes the event and for
// a redelivery (a new delivery number); another event has another.
func TestEventIDIsStable(t *testing.T) {
	s, d, _ := newService(t)
	a, b := &receiver{statuses: []int{204}}, &receiver{statuses: []int{204}}
	sa, sb := httptest.NewServer(a), httptest.NewServer(b)
	defer sa.Close()
	defer sb.Close()
	ida, _, _ := s.Create(sa.URL, []string{store.EventStatus}, "dora")
	if _, _, err := s.Create(sb.URL, []string{store.EventStatus}, "dora"); err != nil {
		t.Fatal(err)
	}
	s.Handle(returned())
	s.RunDue()
	if a.count() != 1 || b.count() != 1 {
		t.Fatal(a.count(), b.count())
	}
	first := a.reqs[0]
	if first.eventID == "" || first.eventID != b.reqs[0].eventID {
		t.Fatalf("two webhooks, one event: %q and %q", first.eventID, b.reqs[0].eventID)
	}
	dl, _ := d.Deliveries(ida, 1)
	if err := s.Redeliver(dl[0].ID); err != nil {
		t.Fatal(err)
	}
	s.RunDue()
	again := a.reqs[1]
	if again.eventID != first.eventID || again.id == first.id {
		t.Fatalf("redelivery %+v after %+v", again, first)
	}
	s.Handle(returned())
	s.RunDue()
	if other := a.reqs[2]; other.eventID == "" || other.eventID == first.eventID {
		t.Fatalf("a second event has the first one's ID %q", other.eventID)
	}
}

// A delivery queued before the event had an ID is sent without the header.
func TestDeliveryWithoutEventID(t *testing.T) {
	s, d, now := newService(t)
	rc := &receiver{statuses: []int{204}}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	id, sec, _ := s.Create(srv.URL, []string{store.EventStatus}, "dora")
	old := `{"event":"finding.status_changed","engagement":"demo"}`
	if _, err := d.EnqueueDelivery(id, store.EventStatus, old, *now); err != nil {
		t.Fatal(err)
	}
	if n, err := s.RunDue(); err != nil || n != 1 || rc.count() != 1 {
		t.Fatal(n, err, rc.count())
	}
	r := rc.reqs[0]
	if r.eventID != "" || string(r.body) != old || r.sig != mac(sec, r.ts+"."+old) {
		t.Fatalf("%+v", r)
	}
}
