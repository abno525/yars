package store

import (
	"errors"
	"testing"

	"yars/internal/workflow"
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
