package store

import (
	"errors"
	"testing"
)

// pre1 6.2: a title written over one read with a base is refused when the
// title changed since; without a base it is not checked. The answer is the
// base of the title as stored.
func TestUpdateTitleFromConflict(t *testing.T) {
	s, _, fd := newFinding(t)
	base := TitleHash(load(t, s, fd).F.Meta)
	nb, err := s.UpdateTitleFrom(eng, fd, "First", base, alice)
	if err != nil || nb == base || nb != TitleHash(load(t, s, fd).F.Meta) {
		t.Fatalf("first: %v, base %q", err, nb)
	}
	if _, err := s.UpdateTitleFrom(eng, fd, "Second", base, bob); !errors.Is(err, ErrConflict) {
		t.Fatalf("a stale base: %v", err)
	}
	if got := load(t, s, fd).F.Meta.Title; got != "First" {
		t.Fatalf("title %q", got)
	}
	if _, err := s.UpdateTitleFrom(eng, fd, "Second", nb, bob); err != nil {
		t.Fatalf("the current base: %v", err)
	}
	if _, err := s.UpdateTitleFrom(eng, fd, "Third", "", bob); err != nil || load(t, s, fd).F.Meta.Title != "Third" {
		t.Fatalf("no base: %v", err)
	}
}

// pre1 6.2: a retest result chosen over one read with a base is refused
// when another result was stored since. The result it already has is no
// conflict (a repeated call), and no base is not checked.
func TestSetRetestResultBaseConflict(t *testing.T) {
	s, _ := srcFixture(t)
	const fd = "F-001-sql-injection"
	if err := s.CreateRetest(Engagement{ID: "rt", Name: "RT"}, eng, []string{fd}, "", uDora); err != nil {
		t.Fatal(err)
	}
	result := func() string {
		ref, err := s.Finding("rt", fd)
		if err != nil || ref.F.Meta.Retest == nil {
			t.Fatalf("retest finding: %v", err)
		}
		return ref.F.Meta.Retest.Result
	}
	none := RetestResultHash("")
	if err := s.SetRetestResultBase("rt", fd, none, "fixed", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRetestResultBase("rt", fd, none, "not_fixed", uAlice); !errors.Is(err, ErrConflict) || result() != "fixed" {
		t.Fatalf("a stale base: %v (%s)", err, result())
	}
	if err := s.SetRetestResultBase("rt", fd, none, "fixed", uAlice); err != nil {
		t.Fatalf("the result it has: %v", err)
	}
	if err := s.SetRetestResultBase("rt", fd, RetestResultHash("fixed"), "not_fixed", uAlice); err != nil || result() != "not_fixed" {
		t.Fatalf("the current base: %v (%s)", err, result())
	}
	if err := s.SetRetestResultBase("rt", fd, "", "partially_fixed", uAlice); err != nil || result() != "partially_fixed" {
		t.Fatalf("no base: %v (%s)", err, result())
	}
}
