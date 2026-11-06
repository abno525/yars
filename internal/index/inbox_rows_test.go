package index

import (
	"testing"
	"time"

	"yars/internal/chat"
	"yars/internal/config"
)

// A row carries what the inbox shows without reading the chat again: each
// open thread with its last message, the workflow events, the time of the
// last message and the hash of the file.
func TestRowInboxFields(t *testing.T) {
	_, s := fixture(t)
	refs, err := s.ListFindings("other")
	if err != nil || len(refs) != 1 {
		t.Fatal(refs, err)
	}
	t1 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	msgs := []chat.Message{
		{ID: "a", TS: t1, User: "alice", Event: "submit"},
		{ID: "b", TS: t1.Add(time.Minute), User: "bob", Text: "Is the **impact** real?", Section: "Impact"},
		{ID: "c", TS: t1.Add(2 * time.Minute), User: "alice", Reply: "b", Text: "Only after login"},
		{ID: "d", TS: t1.Add(3 * time.Minute), User: "bob", Text: "closed one"},
		{ID: "e", TS: t1.Add(4 * time.Minute), User: "bob", Resolves: "d"},
		{ID: "f", TS: t1.Add(5 * time.Minute), User: "yars", Kind: chat.KindCheck, Text: "rule hit"},
		{ID: "g", TS: t1.Add(6 * time.Minute), User: "bob", Event: "clear"},
	}
	r := rowOf("other", refs[0], msgs)
	if len(r.Threads) != 2 {
		t.Fatalf("threads %+v", r.Threads)
	}
	th := r.Threads[0]
	if th.ID != "b" || th.Section != "Impact" || th.Starter != "bob" || th.LastUser != "alice" || th.LastText != "Only after login" || !th.LastTS.Equal(t1.Add(2*time.Minute)) || th.Kind != "" {
		t.Fatalf("thread %+v", th)
	}
	if r.Threads[1].Kind != chat.KindCheck {
		t.Fatalf("check thread %+v", r.Threads[1])
	}
	if len(r.Events) != 2 || r.Events[0].Action != "submit" || r.Events[0].User != "alice" || r.Events[1].Action != "clear" || r.Events[1].User != "bob" {
		t.Fatalf("events %+v", r.Events)
	}
	if !r.Updated.Equal(t1.Add(6 * time.Minute)) {
		t.Fatalf("updated %v", r.Updated)
	}
	if r.Hash == "" || r.Hash != refs[0].Hash {
		t.Fatalf("hash %q, ref %q", r.Hash, refs[0].Hash)
	}
}

// A chat post updates the row's threads in place (no reload).
func TestRowThreadsLive(t *testing.T) {
	ix, s := fixture(t)
	if _, err := ix.Rows(Query{}); err != nil {
		t.Fatal(err)
	}
	bob := config.User{Username: "bob", Role: "reviewer"}
	m, err := s.PostChat("acme", "F-002-b", chat.Message{Text: "why?"}, bob)
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := ix.Rows(Query{EngID: "acme"})
	r := byTitle(t, rows, "B")
	if len(r.Threads) != 1 || r.Threads[0].ID != m.ID || r.Threads[0].LastUser != "bob" {
		t.Fatalf("threads %+v", r.Threads)
	}
	s.PostChat("acme", "F-002-b", chat.Message{Resolves: m.ID}, bob)
	rows, _ = ix.Rows(Query{EngID: "acme"})
	if r := byTitle(t, rows, "B"); len(r.Threads) != 0 {
		t.Fatalf("resolved thread still open %+v", r.Threads)
	}
}
