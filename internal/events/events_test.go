package events

import (
	"sync"
	"testing"
	"time"
)

func recv(t *testing.T, s *Sub) Event {
	t.Helper()
	select {
	case e := <-s.C():
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("no event")
	}
	return Event{}
}

func none(t *testing.T, s *Sub) {
	t.Helper()
	select {
	case e := <-s.C():
		t.Fatalf("unexpected event %+v", e)
	default:
	}
}

func TestFilter(t *testing.T) {
	h := New()
	fin := h.Subscribe("acme", "F-001", 8)
	eng := h.Subscribe("acme", "", 8)
	all := h.Subscribe("", "", 8)
	other := h.Subscribe("beta", "", 8)
	defer h.Unsubscribe(fin)

	e := h.Publish(Event{Eng: "acme", Fid: "F-001", Kind: Chat, Seq: 3})
	if e.ID != 1 || h.Last() != 1 {
		t.Fatalf("id %d last %d", e.ID, h.Last())
	}
	for _, s := range []*Sub{fin, eng, all} {
		if got := recv(t, s); got != e {
			t.Fatalf("got %+v want %+v", got, e)
		}
	}
	none(t, other)

	h.Publish(Event{Eng: "acme", Fid: "F-002", Kind: Workflow})
	none(t, fin)
	recv(t, eng)

	// a push names only the engagement: every finding in it hears it
	h.Publish(Event{Eng: "acme", Kind: Push})
	if got := recv(t, fin); got.Kind != Push {
		t.Fatalf("got %+v", got)
	}
	// a push to the main repo reaches everyone
	h.Publish(Event{Kind: Push})
	recv(t, other)
}

func TestUnsubscribe(t *testing.T) {
	h := New()
	s := h.Subscribe("acme", "", 1)
	h.Unsubscribe(s)
	h.Publish(Event{Eng: "acme", Kind: Chat})
	none(t, s)
	h.Unsubscribe(s) // twice is fine
}

// A slow subscriber loses events but never blocks the writer; it is told
// it lost some.
func TestSlowSubscriberDrops(t *testing.T) {
	h := New()
	s := h.Subscribe("acme", "", 2)
	done := make(chan struct{})
	go func() {
		for range 100 {
			h.Publish(Event{Eng: "acme", Fid: "F-001", Kind: Chat})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher blocked by a slow subscriber")
	}
	select {
	case <-s.Lost():
	default:
		t.Fatal("lost signal not set")
	}
	if n := len(s.C()); n != 2 {
		t.Fatalf("buffered %d", n)
	}
}

func TestMissed(t *testing.T) {
	h := New()
	if h.Missed(0, "acme", "F-001") {
		t.Fatal("nothing published yet")
	}
	h.Publish(Event{Eng: "beta", Fid: "F-001", Kind: Chat}) // 1
	if h.Missed(0, "acme", "F-001") {
		t.Fatal("other engagement counted")
	}
	h.Publish(Event{Eng: "acme", Fid: "F-001", Kind: Chat}) // 2
	if !h.Missed(1, "acme", "F-001") || h.Missed(2, "acme", "F-001") {
		t.Fatal("missed wrong")
	}
	// a client id from the future (server restarted) is out of date too
	if !h.Missed(99, "acme", "F-001") {
		t.Fatal("id beyond the hub's counter should resync")
	}
	// events that fell out of the ring count as missed
	for range ringSize + 5 {
		h.Publish(Event{Eng: "beta", Kind: Chat})
	}
	if !h.Missed(2, "acme", "F-001") {
		t.Fatal("ring overflow should count as missed")
	}
}

func TestConcurrent(t *testing.T) {
	h := New()
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 200 {
				h.Publish(Event{Eng: "acme", Fid: "F-001", Kind: Chat, Seq: int64(i)})
			}
		}()
		go func() {
			defer wg.Done()
			for range 50 {
				s := h.Subscribe("acme", "F-001", 4)
				h.Missed(1, "acme", "F-001")
				h.Unsubscribe(s)
			}
		}()
	}
	wg.Wait()
	if h.Last() != 800 {
		t.Fatalf("last %d", h.Last())
	}
}
