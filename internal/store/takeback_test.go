package store

import (
	"slices"
	"testing"

	"yars/internal/config"
	"yars/internal/workflow"
)

// The author takes a finding in verification back to draft: sign-offs are
// dropped, no reason is needed, and the event is recorded.
func TestTransitionTakeBack(t *testing.T) {
	s, _, fd := ready(t)
	if err := s.Transition(eng, fd, workflow.TakeBack, "", uAlice); !denied(err) {
		t.Fatalf("take back of a draft: %v", err)
	}
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.TakeBack, "", uBob); !denied(err) {
		t.Fatalf("reviewer took back: %v", err)
	}
	if err := s.Transition(eng, fd, workflow.TakeBack, "", config.User{Username: "pen2", Role: "pentester"}); !denied(err) {
		t.Fatalf("other pentester took back: %v", err)
	}
	if err := s.Transition(eng, fd, workflow.TakeBack, "", uAlice); err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if m.Status != "draft" || len(m.ClearedBy) != 0 || m.Returned != nil {
		t.Fatalf("after take back: status %s cleared %v returned %v", m.Status, m.ClearedBy, m.Returned)
	}
	if got := events(t, s, fd); !slices.Contains(got, "alice:take_back:") {
		t.Fatalf("events %v", got)
	}
	// the stored clearances are wiped too, not only hidden
	st, err := s.DB().State(eng, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range st.Reviewers {
		if r.ClearedHash != "" {
			t.Fatalf("clearance kept: %+v", r)
		}
	}
	if st.ReturnedBy != "" || st.ReturnedReason != "" {
		t.Fatalf("returned kept: %q %q", st.ReturnedBy, st.ReturnedReason)
	}
}

// The author marks their own complete finding reported.
func TestTransitionAuthorReport(t *testing.T) {
	s, _, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Report, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if load(t, s, fd).F.Meta.Status != "reported" {
		t.Fatal("not reported")
	}
}

// A reviewer may add reviewers while the finding is open, but never remove
// one: dropping a reviewer who signed off would undo the four-eyes check.
func TestReviewerAssigns(t *testing.T) {
	s, _, fd := ready(t)
	if err := s.SetReviewers(eng, fd, []string{"bob", "carol"}, uCarol); err != nil {
		t.Fatal(err)
	}
	if got := load(t, s, fd).F.Meta.Reviewers; !slices.Equal(got, []string{"bob", "carol"}) {
		t.Fatalf("reviewers %v", got)
	}
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.SetReviewers(eng, fd, []string{"carol"}, uCarol); !denied(err) {
		t.Fatalf("a reviewer dropped the reviewer who signed off: %v", err)
	}
	pen2 := config.User{Username: "pen2", Role: "pentester"}
	if err := s.SetReviewers(eng, fd, []string{"bob", "carol", "dora"}, pen2); !denied(err) {
		t.Fatalf("another pentester added a reviewer: %v", err)
	}
	m := load(t, s, fd).F.Meta
	if !slices.Equal(m.Reviewers, []string{"bob", "carol"}) || !slices.Equal(m.ClearedBy, []string{"bob"}) {
		t.Fatalf("reviewers %v cleared %v", m.Reviewers, m.ClearedBy)
	}
	// the author and directors still change the list
	if err := s.SetReviewers(eng, fd, []string{"carol"}, uDora); err != nil {
		t.Fatal(err)
	}
}
