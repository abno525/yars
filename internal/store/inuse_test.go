package store

import (
	"fmt"
	"slices"
	"testing"

	"yars/internal/config"
)

// R3: names a new configuration drops while findings of any engagement
// (archived ones too) still use them: a section with text, a severity, a
// details row with a value.
func TestDroppedInUse(t *testing.T) {
	s, _ := newStore(t)
	cfg := config.Default()
	cfg.Severities = append(slices.Clone(cfg.Severities), "extreme")
	s.SetConfig(cfg)
	s.CreateEngagement(Engagement{ID: "acme", Name: "ACME"}, alice)
	s.CreateEngagement(Engagement{ID: "old", Name: "Old"}, alice)
	for i := range 12 {
		ref, err := s.CreateFinding("acme", fmt.Sprintf("Finding %d", i), alice)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.UpdateSection("acme", ref.Dir, "Impact", "Full read.", "", bob); err != nil {
			t.Fatal(err)
		}
	}
	ref, err := s.CreateFinding("old", "Old one", alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSeverity("old", ref.Dir, "extreme", "", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateDetails("old", ref.Dir, map[string]string{"Cause": "Old code"}, "", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.Archive("old", m17Dir); err != nil {
		t.Fatal(err)
	}
	now := config.Default()
	now.Sections = slices.DeleteFunc(slices.Clone(now.Sections), func(x string) bool { return x == "Impact" || x == "References" })
	now.DetailsRows = slices.DeleteFunc(slices.Clone(now.DetailsRows), func(x string) bool { return x == "Cause" || x == "Result" })
	uses, err := s.DroppedInUse(cfg, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(uses) != 3 {
		t.Fatalf("uses %+v", uses)
	}
	if u := uses[0]; u.List != "section" || u.Name != "Impact" || len(u.Findings) != 12 || u.Findings[0] != "acme/F-001" {
		t.Errorf("section %+v", u)
	}
	if u := uses[1]; u.List != "severity" || u.Name != "extreme" || !slices.Equal(u.Findings, []string{"old/F-001"}) {
		t.Errorf("severity %+v", u)
	}
	if u := uses[2]; u.List != "details row" || u.Name != "Cause" || !slices.Equal(u.Findings, []string{"old/F-001"}) {
		t.Errorf("details row %+v", u)
	}
	// nothing dropped, or only reordered: nothing to say
	re := cfg
	re.Sections = slices.Clone(cfg.Sections)
	slices.Reverse(re.Sections)
	if uses, _ := s.DroppedInUse(cfg, re); len(uses) != 0 {
		t.Errorf("reorder: %+v", uses)
	}
}
