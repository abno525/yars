package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/workflow"
)

func TestUpdateEngagementSettings(t *testing.T) {
	s, dir := withEngagement(t)
	e, _ := s.Engagement(eng)
	e.Name, e.Client, e.Start, e.End = "ACME portal", "ACME Ltd", "2026-11-04", "2026-11-07"
	var d *workflow.Denied
	if err := s.UpdateEngagement(e, m17Pen); !errors.As(err, &d) {
		t.Fatalf("pentester: %v", err)
	}
	if err := s.UpdateEngagement(e, m17Dir); err != nil {
		t.Fatal(err)
	}
	if got := last(t, dir, "%an|%s"); got != "dora|engagement "+eng+": settings" {
		t.Fatalf("commit %q", got)
	}
	got, _ := s.Engagement(eng)
	if got.Name != "ACME portal" || got.Client != "ACME Ltd" || got.Start != "2026-11-04" || got.End != "2026-11-07" || got.Type != "pentest" {
		t.Fatalf("saved %+v", got)
	}
	bad := got
	bad.Name = " "
	if err := s.UpdateEngagement(bad, m17Dir); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty name: %v", err)
	}
	bad = got
	bad.Start = "4 Nov"
	if err := s.UpdateEngagement(bad, m17Dir); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("bad date: %v", err)
	}
}

// pushEngagementYAML commits text as the engagement's engagement.yaml, as a
// director's push leaves it.
func pushEngagementYAML(t *testing.T, s *Store, dir, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "engagements", eng, "engagement.yaml"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := s.EngRepo(eng)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Commit([]string{"engagement.yaml"}, "pushed", gitrepo.Author{Name: "dora", Email: "dora@yars.local"}); err != nil {
		t.Fatal(err)
	}
	s.Invalidate(eng)
}

// A Settings save rewrites only the lines of the values it changes: a pushed
// engagement.yaml keeps its comments, its other keys and its order. An
// emptied date takes its key away, a save that changes nothing makes no
// commit, and a file written between { } is refused, not rewritten.
func TestUpdateEngagementKeepsTheFile(t *testing.T) {
	s, dir := withEngagement(t)
	const hand = `# kept by the delivery team
client: ACME Corp # billed monthly
scope:
    - app.example
    - api.example
type: pentest
end: "2026-02-01"
name: Old name

# the kick-off
start: "2026-01-05"
`
	pushEngagementYAML(t, s, dir, hand)
	file := func() string {
		b, err := os.ReadFile(filepath.Join(dir, "engagements", eng, "engagement.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	e := Engagement{ID: eng, Name: "New name", Client: "ACME Corp", Start: "2026-01-05", End: "2026-02-01"}
	if err := s.UpdateEngagement(e, m17Dir); err != nil {
		t.Fatal(err)
	}
	if want := strings.Replace(hand, "name: Old name", "name: New name", 1); file() != want {
		t.Fatalf("the save changed more than the name:\n%s", file())
	}
	if got := last(t, dir, "%an|%s"); got != "dora|engagement "+eng+": settings" {
		t.Fatalf("commit %q", got)
	}
	// the same values again: no commit
	head := last(t, dir, "%H")
	if err := s.UpdateEngagement(e, m17Dir); err != nil {
		t.Fatal(err)
	}
	if last(t, dir, "%H") != head {
		t.Fatal("a save that changes nothing made a commit")
	}
	// an emptied date: its key goes, the rest stays
	e.End = ""
	if err := s.UpdateEngagement(e, m17Dir); err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(strings.Replace(hand, "name: Old name", "name: New name", 1), "end: \"2026-02-01\"\n", "", 1)
	if file() != want {
		t.Fatalf("clearing the end:\n%s", file())
	}
	if got, _ := s.Engagement(eng); got.End != "" || got.Start != "2026-01-05" || got.Type != "pentest" {
		t.Fatalf("read back %+v", got)
	}
	// set again: a new key is added at the end
	e.End = "2026-03-01"
	if err := s.UpdateEngagement(e, m17Dir); err != nil {
		t.Fatal(err)
	}
	if got := file(); got != want+"end: \"2026-03-01\"\n" {
		t.Fatalf("setting the end again:\n%s", got)
	}

	// a file the line splice cannot rewrite is refused and left alone
	const flow = "{name: Flow, client: C, type: pentest}\n"
	pushEngagementYAML(t, s, dir, flow)
	head = last(t, dir, "%H")
	err := s.UpdateEngagement(Engagement{ID: eng, Name: "Other", Client: "C"}, m17Dir)
	if !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "one key per line") {
		t.Fatalf("flow style: %v", err)
	}
	if file() != flow || last(t, dir, "%H") != head {
		t.Fatalf("the refused save changed the file:\n%s", file())
	}
}
