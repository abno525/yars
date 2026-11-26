package store

import (
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/workflow"
)

// ownFinding is a checked finding by author, with reviewer assigned: its
// title trips no-sql (an error) and its Impact no-foo (a warning).
func ownFinding(t *testing.T, s *Store, author config.User, reviewer string) string {
	t.Helper()
	ref, err := s.CreateFinding(eng, "SQL in the login of "+author.Username, author.GitAuthor())
	if err != nil {
		t.Fatal(err)
	}
	if got := ref.F.Meta.Author; got != author.Username {
		t.Fatalf("author %q", got)
	}
	if err := s.SetReviewers(eng, ref.Dir, []string{reviewer}, author); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSeverity(eng, ref.Dir, "high", "", author.GitAuthor()); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSection(eng, ref.Dir, "Impact", "a foo here", "", author.GitAuthor()); err != nil {
		t.Fatal(err)
	}
	checked(t, s, ref.Dir)
	return ref.Dir
}

// In the standard workflow an error on your own finding is dismissed by
// another person: the author is refused whatever their role, a reviewer's
// and a director's too, and so is their Restore. A warning stays the
// author's to dismiss. The error then still blocks the author's Submit
// (pre1 2.31, Q6).
func TestOwnErrorNeedsAnotherPerson(t *testing.T) {
	s, dir, _ := ready(t)
	withRules(t, s, dir, checkRules)
	const own = "an error on your own finding is dismissed by another reviewer or a director"

	// bob has the reviewer role and wrote the finding
	fb := ownFinding(t, s, uBob, "carol")
	err := s.DismissWhy(eng, fb, "no-sql", "title", "SQL", "it is fine", uBob)
	if !denied(err) || !strings.Contains(err.Error(), own) {
		t.Fatalf("the author dismissed the error on his own finding: %v", err)
	}
	if ds, _ := s.Dismissals(eng, load(t, s, fb).F.Meta.ID); len(ds) != 0 {
		t.Fatalf("dismissals %+v", ds)
	}
	// the pages ask the same question for the button
	if m := load(t, s, fb).F.Meta; s.CanDismiss(uBob, m, "error") || !s.CanDismiss(uBob, m, "warning") || !s.CanDismiss(uCarol, m, "error") || !s.CanDismiss(uDora, m, "error") || s.CanDismiss(uAlice, m, "error") {
		t.Fatal("CanDismiss on bob's finding")
	}
	// the hole this closes: he cannot submit past the error
	if err := s.Transition(eng, fb, workflow.Submit, "", uBob); !denied(err) || !strings.Contains(err.Error(), "Spell out SQL") {
		t.Fatalf("submit with the error open: %v", err)
	}
	// a warning is his to dismiss, and to restore
	if err := s.DismissWhy(eng, fb, "no-foo", "section:Impact", "foo", "house style", uBob); err != nil {
		t.Fatalf("a warning on his own finding: %v", err)
	}
	if err := s.Undismiss(eng, fb, "no-foo", "section:Impact", "foo", uBob); err != nil {
		t.Fatalf("restoring his warning: %v", err)
	}
	// another reviewer dismisses the error; the author does not restore it
	if err := s.DismissWhy(eng, fb, "no-sql", "title", "SQL", "client's glossary", uCarol); err != nil {
		t.Fatalf("another reviewer: %v", err)
	}
	if err := s.Undismiss(eng, fb, "no-sql", "title", "SQL", uBob); !denied(err) || !strings.Contains(err.Error(), own) {
		t.Fatalf("the author restored the error's dismissal: %v", err)
	}
	if err := s.Undismiss(eng, fb, "no-sql", "title", "SQL", uDora); err != nil {
		t.Fatalf("a director restores: %v", err)
	}
	if err := s.DismissWhy(eng, fb, "no-sql", "title", "SQL", "client's glossary", uDora); err != nil {
		t.Fatalf("a director on a reviewer's finding: %v", err)
	}

	// a director's own finding: another person too
	fd := ownFinding(t, s, uDora, "bob")
	if err := s.DismissWhy(eng, fd, "no-sql", "title", "SQL", "it is fine", uDora); !denied(err) || !strings.Contains(err.Error(), own) {
		t.Fatalf("a director dismissed the error on her own finding: %v", err)
	}
	if err := s.DismissWhy(eng, fd, "no-sql", "title", "SQL", "client's glossary", uBob); err != nil {
		t.Fatalf("a reviewer on the director's finding: %v", err)
	}
}
