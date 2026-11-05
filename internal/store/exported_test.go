package store

import (
	"reflect"
	"testing"

	"yars/internal/workflow"
)

// A destination with mark_reported marks a complete finding reported for
// whoever sent it, pentesters included; the event names the destination.
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
	// a pentester can't press Mark reported, but sending marks it
	if err := s.Transition(eng, fd, workflow.Report, "", uAlice); !denied(err) {
		t.Fatalf("pentester marked by hand: %v", err)
	}
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
