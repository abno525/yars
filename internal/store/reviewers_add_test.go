package store

import (
	"slices"
	"testing"

	"yars/internal/finding"
	"yars/internal/workflow"
)

// AddReviewers merges with the list as it is inside the change: a reviewer
// someone added meanwhile (and their sign-off) stays; the author's name is
// skipped while the other names are still added.
func TestAddReviewersMerges(t *testing.T) {
	s, _, fd := ready(t) // alice's, bob reviews
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.AddReviewers(eng, fd, []string{"alice", "carol"}, uDora); err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if !slices.Equal(m.Reviewers, []string{"bob", "carol"}) || !slices.Equal(m.ClearedBy, []string{"bob"}) {
		t.Fatalf("reviewers %v cleared %v", m.Reviewers, m.ClearedBy)
	}
	// only the author's name: nothing to add
	if err := s.AddReviewers(eng, fd, []string{"alice"}, uDora); !denied(err) {
		t.Fatalf("author as only name: %v", err)
	}
	// names already on the list are no change, not a refusal
	if err := s.AddReviewers(eng, fd, []string{"bob"}, uDora); err != nil {
		t.Fatal(err)
	}
}

// A reviewer adds other reviewers but never themselves: who reviews a
// finding is chosen by someone else (four eyes). The author and directors
// still choose freely.
func TestReviewerCannotAssignSelf(t *testing.T) {
	s, _, fd := ready(t)
	if err := s.AddReviewers(eng, fd, []string{"carol"}, uCarol); !denied(err) {
		t.Fatalf("carol added herself in bulk: %v", err)
	}
	if err := s.SetReviewers(eng, fd, []string{"bob", "carol"}, uCarol); !denied(err) {
		t.Fatalf("carol added herself on the finding page: %v", err)
	}
	if got := load(t, s, fd).F.Meta.Reviewers; !slices.Equal(got, []string{"bob"}) {
		t.Fatalf("reviewers %v", got)
	}
	// carol adds dora; bob may add carol
	if err := s.AddReviewers(eng, fd, []string{"dora"}, uCarol); err != nil {
		t.Fatal(err)
	}
	if err := s.SetReviewers(eng, fd, []string{"bob", "carol", "dora"}, uBob); err != nil {
		t.Fatal(err)
	}
	// a director joins by themselves
	if err := s.SetReviewers(eng, fd, []string{"dora"}, uDora); err != nil {
		t.Fatal(err)
	}
}

// TransitionChecked runs the extra check on the finding as it is inside the
// change, so a rule of the caller (bulk: drafts only) holds even when the
// finding moved since the caller read it.
func TestTransitionChecked(t *testing.T) {
	s, _, fd := ready(t)
	draftsOnly := func(m finding.Meta) error {
		if m.Status != "draft" {
			return &workflow.Denied{Reason: "drafts only"}
		}
		return nil
	}
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.TransitionChecked(eng, fd, workflow.Withdraw, "dup", uAlice, draftsOnly); !denied(err) {
		t.Fatalf("withdrew a finding in verification: %v", err)
	}
	if st := load(t, s, fd).F.Meta.Status; st != "verification" {
		t.Fatalf("status %s", st)
	}
	s.Transition(eng, fd, workflow.TakeBack, "", uAlice)
	if err := s.TransitionChecked(eng, fd, workflow.Withdraw, "dup", uAlice, draftsOnly); err != nil {
		t.Fatal(err)
	}
}

// Only Return and Withdraw carry a reason on their event: text typed in the
// reason panel and then abandoned never lands on a submit.
func TestTransitionReasonOnlyWhenNeeded(t *testing.T) {
	s, _, fd := ready(t)
	var got []string
	s.OnEvent(func(e Event) {
		if e.Kind == EventStatus {
			got = append(got, e.Action+":"+e.Reason)
		}
	})
	s.Transition(eng, fd, workflow.Submit, "stray text", uAlice)
	s.Transition(eng, fd, workflow.Return, "add proof", uBob)
	if !slices.Equal(got, []string{"submit:", "return:add proof"}) {
		t.Fatalf("events %v", got)
	}
}
