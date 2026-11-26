package store

import (
	"reflect"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/workflow"
)

// A destination with mark_reported marks a complete finding reported for
// its author or a director, never for another sender; the event names the
// destination.
func TestMarkExported(t *testing.T) {
	s, _, fd := ready(t)
	if err := s.MarkExported(eng, fd, "Jira", uAlice); !denied(err) {
		t.Fatalf("draft marked: %v", err)
	}
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	// a pentester other than the author can't press Mark reported, and a
	// send of theirs marks nothing either; nor does a reviewer's
	pen2 := config.User{Username: "pen2", Role: "pentester"}
	if err := s.Transition(eng, fd, workflow.Report, "", pen2); !denied(err) {
		t.Fatalf("other pentester marked by hand: %v", err)
	}
	for _, u := range []config.User{pen2, uBob} {
		if err := s.MarkExported(eng, fd, "Jira", u); !denied(err) {
			t.Fatalf("%s's send marked: %v", u.Username, err)
		}
	}
	if st := load(t, s, fd).F.Meta.Status; st != "complete" {
		t.Fatalf("a refused sender left it %s", st)
	}
	// a director's send marks anyone's finding
	if err := s.MarkExported(eng, fd, "Jira", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Unreport, "sent too early", uDora); err != nil {
		t.Fatal(err)
	}
	// the author's send marks it
	if err := s.MarkExported(eng, fd, "Jira", uAlice); err != nil {
		t.Fatal(err)
	}
	if load(t, s, fd).F.Meta.Status != "reported" {
		t.Fatal("not reported")
	}
	got := events(t, s, fd)
	if !reflect.DeepEqual(got[len(got)-1], "alice:report:Jira") {
		t.Fatalf("events %v", got)
	}
	// only once
	if err := s.MarkExported(eng, fd, "Jira", uAlice); !denied(err) {
		t.Fatalf("reported twice: %v", err)
	}
}
