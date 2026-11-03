package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"yars/internal/chat"
	"yars/internal/workflow"
)

func TestPostChat(t *testing.T) {
	s, dir, fd := newFinding(t)
	root, err := s.PostChat(eng, fd, chat.Message{Text: "Is this exploitable unauthenticated?", Section: "Impact"}, uBob)
	if err != nil {
		t.Fatal(err)
	}
	if root.ID == "" || root.User != "bob" || root.TS.IsZero() {
		t.Fatalf("root %+v", root)
	}
	if got := last(t, dir, "%an|%s"); got != "bob|F-001: comment" {
		t.Fatalf("commit %q", got)
	}
	if _, err := s.PostChat(eng, fd, chat.Message{Text: "Yes", Reply: root.ID}, uAlice); err != nil {
		t.Fatal(err)
	}
	if got := last(t, dir, "%an|%s"); got != "alice|F-001: reply" {
		t.Fatalf("commit %q", got)
	}
	if _, err := s.PostChat(eng, fd, chat.Message{Resolves: root.ID}, uBob); err != nil {
		t.Fatal(err)
	}
	if got := last(t, dir, "%s"); got != "F-001: resolve thread" {
		t.Fatalf("commit %q", got)
	}
	msgs, err := s.Chat(eng, fd)
	if err != nil || len(msgs) != 3 {
		t.Fatalf("msgs %d %v", len(msgs), err)
	}
	ga, _ := os.ReadFile(filepath.Join(dir, ".gitattributes"))
	if !strings.Contains(string(ga), "chat.jsonl merge=union") {
		t.Fatalf(".gitattributes %q", ga)
	}
	if out, _ := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); len(out) != 0 {
		t.Fatalf("uncommitted: %s", out)
	}
}

func TestPostChatRejectsBadRefs(t *testing.T) {
	s, dir, fd := newFinding(t)
	before := last(t, dir, "%H")
	for _, m := range []chat.Message{{Text: "x", Reply: "missing"}, {Resolves: "missing"}, {Text: " "}, {Text: "x", Section: "Nope"}} {
		if _, err := s.PostChat(eng, fd, m, uBob); !errors.Is(err, ErrInvalidChat) {
			t.Errorf("%+v: err %v", m, err)
		}
	}
	if last(t, dir, "%H") != before {
		t.Fatal("commit made")
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
	s, dir, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Return, "needs PoC", uBob); err != nil {
		t.Fatal(err)
	}
	files, _ := exec.Command("git", "-C", dir, "show", "--name-only", "--format=", "HEAD").Output()
	if !strings.Contains(string(files), "finding.md") || !strings.Contains(string(files), "chat.jsonl") {
		t.Fatalf("files in commit: %s", files)
	}
	msgs, _ := s.Chat(eng, fd)
	if len(msgs) != 2 || msgs[0].Event != "submit" || msgs[1].Event != "return" || msgs[1].Text != "needs PoC" || msgs[1].User != "bob" {
		t.Fatalf("msgs %+v", msgs)
	}
}
