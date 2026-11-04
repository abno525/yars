package store

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/workflow"
)

var (
	uAlice = config.User{Username: "alice", Role: "pentester"}
	uBob   = config.User{Username: "bob", Role: "reviewer"}
	uCarol = config.User{Username: "carol", Role: "reviewer"}
	uDora  = config.User{Username: "dora", Role: "director"}
)

func denied(err error) bool {
	var d *workflow.Denied
	return errors.As(err, &d)
}

// ready returns a finding by alice with bob as reviewer and a severity.
func ready(t *testing.T) (*Store, string, string) {
	t.Helper()
	s, dir, fd := newFinding(t)
	if err := s.SetReviewers(eng, fd, []string{"bob"}, uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSeverity(eng, fd, "high", "", alice); err != nil {
		t.Fatal(err)
	}
	return s, dir, fd
}

func TestTransitionSubmitGate(t *testing.T) {
	s, dir, fd := newFinding(t)
	before := last(t, dir, "%H")
	err := s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if !denied(err) || !strings.Contains(err.Error(), "reviewer") {
		t.Fatalf("err %v", err)
	}
	if last(t, dir, "%H") != before {
		t.Fatal("commit made")
	}
	s, dir, fd = ready(t)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if load(t, s, fd).F.Meta.Status != "verification" || last(t, dir, "%an|%s") != "alice|F-001: submit for verification" {
		t.Fatal("submit not recorded")
	}
}

// A director who reviews without being assigned joins the reviewers in the
// same commit, so their clearance counts for another director's approval.
func TestDirectorClearsUnassigned(t *testing.T) {
	s, _, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Clear, "", uDora); err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if !reflect.DeepEqual(m.Reviewers, []string{"bob", "dora"}) || !reflect.DeepEqual(m.ClearedBy, []string{"dora"}) {
		t.Fatalf("reviewers %v cleared %v", m.Reviewers, m.ClearedBy)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); !denied(err) {
		t.Fatalf("director approved own review: %v", err)
	}
	adm := config.User{Username: "adm", Role: "admin"}
	if err := s.Transition(eng, fd, workflow.Approve, "", adm); err != nil {
		t.Fatal(err)
	}
}

func TestTransitionFlow(t *testing.T) {
	s, dir, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if got := last(t, dir, "%an|%s"); got != "bob|F-001: cleared by bob" {
		t.Fatalf("commit %q", got)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if m.Status != "complete" || !reflect.DeepEqual(m.ClearedBy, []string{"bob"}) || last(t, dir, "%s") != "F-001: approve" {
		t.Fatalf("meta %+v", m)
	}
	if err := s.Transition(eng, fd, workflow.Reopen, "", uDora); err != nil {
		t.Fatal(err)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "verification" || len(m.ClearedBy) != 0 {
		t.Fatalf("reopen %+v", m)
	}
}

func TestTransitionReturnNeedsReason(t *testing.T) {
	s, dir, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	before := last(t, dir, "%H")
	if err := s.Transition(eng, fd, workflow.Return, "  ", uBob); !denied(err) {
		t.Fatalf("err %v", err)
	}
	if last(t, dir, "%H") != before {
		t.Fatal("commit made")
	}
	if err := s.Transition(eng, fd, workflow.Return, "fix steps", uBob); err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if m.Status != "draft" || m.Returned == nil || m.Returned.Reason != "fix steps" || m.Returned.By != "bob" {
		t.Fatalf("meta %+v", m)
	}
	if body := last(t, dir, "%s%n%b"); !strings.Contains(body, "F-001: return to draft") || !strings.Contains(body, "fix steps") {
		t.Fatalf("commit %q", body)
	}
	// resubmitting clears the returned marker
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if load(t, s, fd).F.Meta.Returned != nil {
		t.Fatal("returned kept after submit")
	}
}

func TestEditResetsClearances(t *testing.T) {
	s, _, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	if err := s.UpdateSection(eng, fd, "Impact", "changed after review", "", alice); err != nil {
		t.Fatal(err)
	}
	if c := load(t, s, fd).F.Meta.ClearedBy; len(c) != 0 {
		t.Fatalf("cleared_by kept: %v", c)
	}
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	s.UpdateDetails(eng, fd, map[string]string{"Location": "x"}, "", alice)
	if c := load(t, s, fd).F.Meta.ClearedBy; len(c) != 0 {
		t.Fatalf("cleared_by kept after details edit: %v", c)
	}
}

// The edit lock is enforced inside the store (against the freshly loaded
// finding), not only by the web layer, so an approve racing an edit can't
// let unreviewed text into a complete finding.
func TestContentEditDeniedWhenLocked(t *testing.T) {
	s, dir, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	s.Transition(eng, fd, workflow.Approve, "", uDora)
	before := last(t, dir, "%H")
	if err := s.UpdateSection(eng, fd, "Impact", "late edit", "", uAlice); !denied(err) {
		t.Fatalf("section: %v", err)
	}
	if err := s.UpdateDetails(eng, fd, map[string]string{"Location": "x"}, "", uAlice); !denied(err) {
		t.Fatalf("details: %v", err)
	}
	if err := s.UpdateCVSS(eng, fd, "", nil, "", uAlice); !denied(err) {
		t.Fatalf("cvss: %v", err)
	}
	if err := s.UpdateSeverity(eng, fd, "low", "", uAlice); !denied(err) {
		t.Fatalf("severity: %v", err)
	}
	if last(t, dir, "%H") != before {
		t.Fatal("locked finding changed")
	}
	if err := s.UpdateSection(eng, fd, "Impact", "director fix", "", uDora); err != nil {
		t.Fatalf("director edit: %v", err)
	}
}

func TestSetReviewersDropsClearance(t *testing.T) {
	s, dir, fd := ready(t)
	s.SetReviewers(eng, fd, []string{"bob", "carol"}, uAlice)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	s.Transition(eng, fd, workflow.Clear, "", uCarol)
	if err := s.SetReviewers(eng, fd, []string{"carol"}, uAlice); err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if !reflect.DeepEqual(m.Reviewers, []string{"carol"}) || !reflect.DeepEqual(m.ClearedBy, []string{"carol"}) {
		t.Fatalf("meta %+v", m)
	}
	if got := last(t, dir, "%s"); got != "F-001: set reviewers carol" {
		t.Fatalf("commit %q", got)
	}
}

func TestSetReviewersDropsAuthor(t *testing.T) {
	s, _, fd := newFinding(t)
	if err := s.SetReviewers(eng, fd, []string{"carol", "alice", "bob", "bob"}, uAlice); err != nil {
		t.Fatal(err)
	}
	if r := load(t, s, fd).F.Meta.Reviewers; !reflect.DeepEqual(r, []string{"bob", "carol"}) {
		t.Fatalf("reviewers %v", r)
	}
	if err := s.SetReviewers(eng, fd, []string{"bob"}, config.User{Username: "pen2", Role: "pentester"}); !denied(err) {
		t.Fatalf("non-author assigned: %v", err)
	}
}
