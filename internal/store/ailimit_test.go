package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/rules"
)

// limitFixer is fakeFixer with an AI spend limit that is reached or not.
type limitFixer struct {
	*fakeFixer
	over bool
}

func (l *limitFixer) AIOverLimit() bool { return l.over }

// With the AI spend limit reached Fix with AI is refused at the press, with
// words, and nothing is marked running. A limit reached in the middle of a
// fix answers the item's thread with the words.
func TestFixRefusedOverTheAILimit(t *testing.T) {
	s, _, fd, ff := fixReady(t, "a foo here", "", removeFoo)
	l := &limitFixer{fakeFixer: ff, over: true}
	s.Linter = l
	err := s.StartFix(eng, fd, uAlice)
	s.WaitChecks()
	if !errors.Is(err, ErrInvalidValue) || !strings.HasSuffix(err.Error(), ": the AI spend limit is reached") {
		t.Fatalf("a fix over the limit: %v", err)
	}
	if ff.calls != 0 || s.FixRunning(eng, fidOf(t, s, fd)) || len(aiReplies(t, s, fd)) != 0 {
		t.Fatalf("the fix ran: %d calls, replies %+v", ff.calls, aiReplies(t, s, fd))
	}
	// reached after the press: the provider's refusal is the item's reply
	l.over = false
	ff.fn = func(rules.Violation, string, string) (string, error) { return "", rules.ErrAILimit }
	fixed(t, s, fd)
	if got := aiReplies(t, s, fd); len(got) != 1 || got[0].Text != "Not fixed: the AI spend limit is reached." {
		t.Fatalf("replies %+v", got)
	}
}
