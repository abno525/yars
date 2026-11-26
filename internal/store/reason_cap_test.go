package store

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/workflow"
)

// A reason goes into the chat, notifications, webhooks and mail: the store
// takes at most MaxReason characters of it, whichever page or tool sends it.
func TestReasonCap(t *testing.T) {
	if MaxReason != 4000 {
		t.Fatalf("MaxReason %d", MaxReason)
	}
	long := strings.Repeat("é", MaxReason+1)
	most := " " + strings.Repeat("é", MaxReason) + " " // the cap counts characters, after trimming
	refused := func(t *testing.T, s *Store, fd string, act workflow.Action, u config.User) {
		t.Helper()
		status, evs := load(t, s, fd).F.Meta.Status, events(t, s, fd)
		err := s.Transition(eng, fd, act, long, u)
		if !denied(err) || !strings.Contains(err.Error(), "longer than "+strconv.Itoa(MaxReason)+" characters") {
			t.Fatalf("%s with a reason of %d characters: %v", act, MaxReason+1, err)
		}
		if got := load(t, s, fd).F.Meta.Status; got != status {
			t.Fatalf("a refused %s moved it to %s", act, got)
		}
		if got := events(t, s, fd); !reflect.DeepEqual(got, evs) {
			t.Fatalf("a refused %s wrote to the chat: %v", act, got)
		}
		if err := s.Transition(eng, fd, act, most, u); err != nil {
			t.Fatalf("%s with a reason of %d characters: %v", act, MaxReason, err)
		}
	}
	s, _, fd := ready(t)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	refused(t, s, fd, workflow.Return, uBob)
	refused(t, s, fd, workflow.Withdraw, uDora)
	s, fd = completed(t)
	if err := s.Transition(eng, fd, workflow.Report, "", uDora); err != nil {
		t.Fatal(err)
	}
	refused(t, s, fd, workflow.Unreport, uDora)
	refused(t, s, fd, workflow.Reopen, uDora)
}

// The reason of a dismissal has the same cap.
func TestDismissReasonCap(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, todoRule)
	s.UpdateSection(eng, fd, "Description", "a TODO here", "", alice)
	checked(t, s, fd)
	err := s.DismissWhy(eng, fd, "todo", "section:Description", "TODO", strings.Repeat("é", MaxReason+1), uBob)
	if !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "longer than "+strconv.Itoa(MaxReason)+" characters") {
		t.Fatalf("dismiss with a reason of %d characters: %v", MaxReason+1, err)
	}
	if open, err := s.OpenChecks(eng, fd); err != nil || len(open) != 1 {
		t.Fatalf("a refused dismissal counted: %+v %v", open, err)
	}
	if err := s.DismissWhy(eng, fd, "todo", "section:Description", "TODO", strings.Repeat("é", MaxReason), uBob); err != nil {
		t.Fatal(err)
	}
}
