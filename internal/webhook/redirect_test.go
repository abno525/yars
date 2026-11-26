package webhook

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/store"
)

// A webhook endpoint that redirects to another host gets no follow-up: the
// signed payload goes only to the address the webhook was made for. A
// redirect on the same host is followed (pre1 2.26).
func TestRedirectToAnotherHostRefused(t *testing.T) {
	s, d, _ := newService(t)
	other := &receiver{statuses: []int{204}}
	otherSrv := httptest.NewServer(other)
	defer otherSrv.Close()
	hits := 0
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.Redirect(w, r, otherSrv.URL+"/collect", http.StatusTemporaryRedirect) // 307: the body would follow
	}))
	defer first.Close()
	id, _, err := s.Create(first.URL+"/hook", []string{store.EventStatus}, "dora")
	if err != nil {
		t.Fatal(err)
	}
	s.Handle(returned())
	if _, err := s.RunDue(); err != nil {
		t.Fatal(err)
	}
	if hits != 1 || other.count() != 0 {
		t.Fatalf("%d requests to the webhook's address, %d followed the redirect to another host", hits, other.count())
	}
	l, _ := d.Deliveries(id, 1)
	host := strings.TrimPrefix(otherSrv.URL, "http://")
	if l[0].State != db.DeliveryPending || l[0].Error != "redirect to "+host+" refused" {
		t.Fatalf("delivery %+v", l[0])
	}

	// the same host and port, another path: followed
	rc := &receiver{statuses: []int{204}}
	mux := http.NewServeMux()
	mux.HandleFunc("/hook", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/hook/", http.StatusPermanentRedirect)
	})
	mux.Handle("/hook/", rc)
	same := httptest.NewServer(mux)
	defer same.Close()
	id2, _, _ := s.Create(same.URL+"/hook", []string{store.EventCreated}, "dora")
	s.Handle(store.Event{Kind: store.EventCreated, Eng: "demo", Fid: "F-002", Dir: "F-002-x"})
	s.RunDue()
	if l, _ := d.Deliveries(id2, 1); l[0].State != db.DeliveryOK || rc.count() != 1 || rc.reqs[0].sig == "" || len(rc.reqs[0].body) == 0 {
		t.Fatalf("a redirect on the same host: %+v, %d requests", l[0], rc.count())
	}
}
