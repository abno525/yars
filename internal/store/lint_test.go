package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"yars/internal/rules"
)

const dotRule = "- id: title-no-trailing-dot\n  target: title\n  regex_forbid: '\\.$'\n  message: The title ends with a dot\n"

// withDot is the finding's file with its title ending in a dot.
func withDot(t *testing.T, s *Store, fd string) []byte {
	t.Helper()
	ref := load(t, s, fd)
	raw := string(ref.F.Bytes())
	title := ref.F.Meta.Title
	if !strings.Contains(raw, "title: "+title+"\n") {
		t.Fatalf("no title line in:\n%s", raw)
	}
	return []byte(strings.Replace(raw, "title: "+title+"\n", "title: "+title+".\n", 1))
}

// M30: posted content is checked with every rule, as a check run does.
func TestLintContent(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, dotRule)
	vs, err := s.LintContent(context.Background(), eng, withDot(t, s, fd))
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || vs[0].Rule != "title-no-trailing-dot" {
		t.Fatalf("violations %+v", vs)
	}
	if vs, err := s.LintContent(context.Background(), eng, load(t, s, fd).F.Bytes()); err != nil || len(vs) != 0 {
		t.Fatalf("clean: %+v %v", vs, err)
	}
	if _, err := s.LintContent(context.Background(), eng, []byte("---\ntitle: [\n---\n")); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("unparseable: %v", err)
	}
	if _, err := s.LintContent(context.Background(), "nope", load(t, s, fd).F.Bytes()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown engagement: %v", err)
	}
	// no linter: nothing to find
	s.Linter = nil
	if vs, err := s.LintContent(context.Background(), eng, withDot(t, s, fd)); err != nil || len(vs) != 0 {
		t.Fatalf("no linter: %+v %v", vs, err)
	}
}

// M30: a violation dismissed on that finding is not reported.
func TestLintContentHonoursDismissals(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, dotRule)
	// a dismissal is made on the finding as the server holds it
	if err := s.UpdateTitle(eng, fd, load(t, s, fd).F.Meta.Title+".", alice); err != nil {
		t.Fatal(err)
	}
	raw := load(t, s, fd).F.Bytes()
	vs, err := s.LintContent(context.Background(), eng, raw)
	if err != nil || len(vs) != 1 {
		t.Fatalf("violations %+v %v", vs, err)
	}
	if err := s.DismissWhy(eng, fd, vs[0].Rule, vs[0].Target, vs[0].Quote, "house style", uBob); err != nil {
		t.Fatal(err)
	}
	if vs, err := s.LintContent(context.Background(), eng, raw); err != nil || len(vs) != 0 {
		t.Fatalf("after the dismissal: %+v %v", vs, err)
	}
}

// M30 (D24): the AI calls of a lint are recorded under the finding posted.
func TestLintContentNamesTheFinding(t *testing.T) {
	s, _, fd := ready(t)
	var got []rules.Caller
	s.Linter = callerLinter{&got}
	ctx := rules.WithCaller(context.Background(), rules.Caller{User: "alice"})
	if _, err := s.LintContent(ctx, eng, load(t, s, fd).F.Bytes()); err != nil {
		t.Fatal(err)
	}
	id := load(t, s, fd).F.Meta.ID
	if len(got) != 1 || got[0] != (rules.Caller{User: "alice", Eng: eng, Fid: id}) {
		t.Fatalf("callers %+v", got)
	}
	// a posted id that is not a finding id is not recorded
	raw := strings.Replace(string(load(t, s, fd).F.Bytes()), "id: "+id+"\n", "id: "+strings.Repeat("x", 300)+"\n", 1)
	got = nil
	if _, err := s.LintContent(ctx, eng, []byte(raw)); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Fid != "" {
		t.Fatalf("callers %+v", got)
	}
}
