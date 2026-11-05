package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"yars/internal/chat"
	"yars/internal/workflow"
)

func chatMsg(text string) chat.Message { return chat.Message{Text: text} }

// Chat lives in the database: posting makes no commit and writes no file.
func TestPostChat(t *testing.T) {
	s, dir, fd := newFinding(t)
	before := last(t, dir, "%H")
	root, err := s.PostChat(eng, fd, chat.Message{Text: "Is this exploitable unauthenticated?", Section: "Impact"}, uBob)
	if err != nil {
		t.Fatal(err)
	}
	if root.ID == "" || root.User != "bob" || root.TS.IsZero() {
		t.Fatalf("root %+v", root)
	}
	if _, err := s.PostChat(eng, fd, chat.Message{Text: "Yes", Reply: root.ID}, uAlice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PostChat(eng, fd, chat.Message{Resolves: root.ID}, uBob); err != nil {
		t.Fatal(err)
	}
	msgs, err := s.Chat(eng, fd)
	if err != nil || len(msgs) != 3 || msgs[0].Section != "Impact" || msgs[1].Reply != root.ID {
		t.Fatalf("msgs %+v %v", msgs, err)
	}
	if last(t, dir, "%H") != before {
		t.Fatal("chat made a git commit")
	}
	if _, err := os.Stat(filepath.Join(dir, "engagements", eng, "findings", fd, "chat.jsonl")); err == nil {
		t.Fatal("chat.jsonl written")
	}
}

// Hiding a resolved thread is personal: other users still see it.
func TestHideThreadPerUser(t *testing.T) {
	s, _, fd := newFinding(t)
	root, _ := s.PostChat(eng, fd, chat.Message{Text: "x"}, uBob)
	open, _ := s.PostChat(eng, fd, chat.Message{Text: "y"}, uBob)
	if err := s.HideThread(eng, fd, root.ID, true, uAlice); !errors.Is(err, ErrInvalidChat) {
		t.Fatalf("hid an open thread: %v", err)
	}
	if err := s.HideThread(eng, fd, "missing", true, uAlice); !errors.Is(err, ErrInvalidChat) {
		t.Fatalf("hid a missing thread: %v", err)
	}
	s.PostChat(eng, fd, chat.Message{Resolves: root.ID}, uBob)
	if err := s.HideThread(eng, fd, root.ID, true, uAlice); err != nil {
		t.Fatal(err)
	}
	if h, err := s.HiddenThreads(eng, fd, uAlice); err != nil || !h[root.ID] || h[open.ID] {
		t.Fatalf("alice hidden %v %v", h, err)
	}
	if h, _ := s.HiddenThreads(eng, fd, uBob); len(h) != 0 {
		t.Fatalf("bob hidden %v", h)
	}
	if err := s.HideThread(eng, fd, root.ID, false, uAlice); err != nil {
		t.Fatal(err)
	}
	if h, _ := s.HiddenThreads(eng, fd, uAlice); len(h) != 0 {
		t.Fatalf("after show %v", h)
	}
}

func TestPostChatRejectsBadRefs(t *testing.T) {
	s, _, fd := newFinding(t)
	for _, m := range []chat.Message{{Text: "x", Reply: "missing"}, {Resolves: "missing"}, {Text: " "}, {Text: "x", Section: "Nope"}} {
		if _, err := s.PostChat(eng, fd, m, uBob); !errors.Is(err, ErrInvalidChat) {
			t.Errorf("%+v: err %v", m, err)
		}
	}
	if msgs, _ := s.Chat(eng, fd); len(msgs) != 0 {
		t.Fatalf("stored %d rejected messages", len(msgs))
	}
}

func TestResolveDropsText(t *testing.T) {
	s, _, fd := newFinding(t)
	root, _ := s.PostChat(eng, fd, chat.Message{Text: "x"}, uBob)
	got, err := s.PostChat(eng, fd, chat.Message{Resolves: root.ID, Text: strings.Repeat("A", 50000), Section: "Impact"}, uBob)
	if err != nil {
		t.Fatal(err)
	}
	msgs, _ := s.Chat(eng, fd)
	if got.Text != "" || msgs[1].Text != "" || msgs[1].Section != "" {
		t.Fatalf("resolve kept text (%d chars) / section %q", len(msgs[1].Text), msgs[1].Section)
	}
}

func TestPostChatConcurrent(t *testing.T) {
	s, _, fd := newFinding(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.PostChat(eng, fd, chat.Message{Text: "hi"}, uBob); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if msgs, _ := s.Chat(eng, fd); len(msgs) != 20 {
		t.Fatalf("got %d messages", len(msgs))
	}
}

func TestTransitionWritesEvent(t *testing.T) {
	s, _, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Return, "needs PoC", uBob); err != nil {
		t.Fatal(err)
	}
	msgs, _ := s.Chat(eng, fd)
	if len(msgs) != 2 || msgs[0].Event != "submit" || msgs[1].Event != "return" || msgs[1].Text != "needs PoC" || msgs[1].User != "bob" {
		t.Fatalf("msgs %+v", msgs)
	}
}
