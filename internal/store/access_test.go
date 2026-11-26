package store

import (
	"errors"
	"slices"
	"testing"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/workflow"
)

func TestVisibility(t *testing.T) {
	s, _ := withEngagement(t)
	if s.CanSee(uAlice, eng) {
		t.Fatal("non-member sees the engagement")
	}
	if err := s.AddMembers(eng, []string{"alice"}, uDora); err != nil {
		t.Fatal(err)
	}
	if !s.CanSee(uAlice, eng) || s.CanSee(uBob, eng) {
		t.Fatal("membership")
	}
	// directors and admins see every engagement
	admin := config.User{Username: "ann", Role: "pentester", IsAdmin: true}
	if !s.CanSee(uDora, eng) || !s.CanSee(admin, eng) {
		t.Fatal("director or admin can't see")
	}
	if v, _ := s.Visible(uDora); v != nil {
		t.Fatalf("director's set %v", v)
	}
	if v, _ := s.Visible(uAlice); !v[eng] || len(v) != 1 {
		t.Fatalf("alice's set %v", v)
	}
	if v, _ := s.Visible(uBob); v == nil || len(v) != 0 {
		t.Fatalf("bob's set %v", v)
	}
	// only directors and admins change the team
	if err := s.AddMembers(eng, []string{"bob"}, uAlice); !denied(err) {
		t.Fatalf("pentester changed the team: %v", err)
	}
	if err := s.RemoveMember(eng, "alice", admin); err != nil {
		t.Fatal(err)
	}
	if s.CanSee(uAlice, eng) {
		t.Fatal("removed member still sees it")
	}
	l, _ := s.DB().AuditLog(10)
	if len(l) != 2 || l[0].Action != "eng.member.remove" || l[0].Actor != "ann" || l[1].Action != "eng.member.add" || l[1].Target != eng {
		t.Fatalf("audit %+v", l)
	}
	// without a database (a local clone) everything is visible
	nodb := New(s.repo, config.Default(), nil)
	if !nodb.CanSee(uAlice, eng) {
		t.Fatal("clone hides engagements")
	}
}

func TestArchiveIsReadOnly(t *testing.T) {
	s, _, fd := ready(t)
	if _, err := s.PostChat(eng, fd, chat.Message{Text: "before"}, uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Archive(eng, uAlice); !denied(err) {
		t.Fatalf("pentester archived: %v", err)
	}
	if err := s.Archive(eng, uDora); err != nil {
		t.Fatal(err)
	}
	if !s.Archived(eng) {
		t.Fatal("not archived")
	}
	if e, _ := s.Engagement(eng); !e.Archived {
		t.Fatal("engagement does not say archived")
	}
	writes := map[string]error{
		"section":   s.UpdateSection(eng, fd, "Impact", "x", "", uAlice),
		"title":     s.UpdateTitle(eng, fd, "New", uDora),
		"severity":  s.UpdateSeverity(eng, fd, "low", "", uAlice),
		"details":   s.UpdateDetails(eng, fd, map[string]string{"Location": "x"}, "", uAlice),
		"submit":    s.Transition(eng, fd, workflow.Submit, "", uAlice),
		"reviewers": s.SetReviewers(eng, fd, []string{"carol"}, uDora),
	}
	_, writes["chat"] = s.PostChat(eng, fd, chat.Message{Text: "after"}, uBob)
	_, writes["create"] = s.CreateFinding(eng, "Another", alice)
	_, writes["check"] = s.StartCheck(eng, fd, uAlice)
	writes["dismiss"] = s.Dismiss(eng, fd, "r", "q", uDora)
	for k, err := range writes {
		if !errors.Is(err, ErrArchived) {
			t.Errorf("%s on an archived engagement: %v", k, err)
		}
	}
	// reading still works
	if _, err := s.Finding(eng, fd); err != nil {
		t.Fatal(err)
	}
	if msgs, _ := s.Chat(eng, fd); len(msgs) != 1 {
		t.Fatalf("chat %+v", msgs)
	}
	// reopening is for directors only (an admin flag is not enough)
	if err := s.Unarchive(eng, config.User{Username: "ann", Role: "reviewer", IsAdmin: true}); !denied(err) {
		t.Fatalf("non-director reopened: %v", err)
	}
	if err := s.Unarchive(eng, uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSection(eng, fd, "Impact", "x", "", uAlice); err != nil {
		t.Fatal(err)
	}
	l, _ := s.DB().AuditLog(10)
	if len(l) != 2 || l[0].Action != "eng.unarchive" || l[1].Action != "eng.archive" || l[1].Actor != "dora" {
		t.Fatalf("audit %+v", l)
	}
}

// A retest starts with the source's team plus the retester.
func TestRetestCopiesTeam(t *testing.T) {
	s, _, fd := newFinding(t)
	s.AddMembers(eng, []string{"alice", "bob"}, uDora)
	if err := s.CreateRetest(Engagement{ID: "rt", Name: "Retest"}, eng, []string{fd}, "carol", uDora); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.DB().Members("rt"); !slices.Equal(m, []string{"alice", "bob", "carol"}) {
		t.Fatalf("team %v", m)
	}
	// an archived source can still be retested
	s.Archive(eng, uDora)
	if err := s.CreateRetest(Engagement{ID: "rt2", Name: "Retest 2"}, eng, []string{fd}, "", uDora); err != nil {
		t.Fatal(err)
	}
}

func TestSettingsCommitAudited(t *testing.T) {
	s, _ := newStore(t)
	err := s.EditSettings("rules: add r1", uDora.GitAuthor(), func(read func(string) ([]byte, error)) ([]SettingsFile, error) {
		return []SettingsFile{{Path: ".yars/rules/r1.yaml", Data: []byte("- id: r1\n")}}, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := s.DB().AuditLog(10)
	if len(l) != 1 || l[0].Action != "settings" || l[0].Actor != "dora" || l[0].Detail != "rules: add r1" {
		t.Fatalf("audit %+v", l)
	}
}
