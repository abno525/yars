package web

import (
	"net/url"
	"strings"
	"testing"
)

// Open threads is a pentester's and a reviewer's queue: a director who wrote
// a finding with an open thread gets no Open threads queue (board 2.2).
func TestInboxDirectorNoThreads(t *testing.T) {
	e := setup(t)
	ref, err := e.srv.Store.CreateFinding("acme", "Weak TLS", e.authorOf(wDora))
	if err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "bob", "POST", findingURL("acme", ref.Dir)+"/chat", url.Values{"text": {"is this current?"}}, nil); rec.Code != 200 {
		t.Fatalf("chat %d", rec.Code)
	}
	b := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	names, _ := queues(b)
	if got := strings.Join(names, ","); strings.Contains(got, "Open threads") {
		t.Fatalf("dora: %s", got)
	}
	if strings.Contains(b, "is this current?") {
		t.Fatal("the thread is in dora's inbox")
	}
}
