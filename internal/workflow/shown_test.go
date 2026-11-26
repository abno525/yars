package workflow

import (
	"slices"
	"testing"

	"github.com/abno525/yars/internal/finding"
)

// A finding in verification whose every assigned reviewer has signed off
// shows as signed off; the stored status stays verification.
func TestShown(t *testing.T) {
	for _, c := range []struct {
		m    finding.Meta
		want string
	}{
		{finding.Meta{Status: "draft"}, "draft"},
		{finding.Meta{Status: "verification"}, "verification"},
		{finding.Meta{Status: "verification", Reviewers: []string{"bob", "rev2"}, ClearedBy: []string{"bob"}}, "verification"},
		{finding.Meta{Status: "verification", Reviewers: []string{"bob", "rev2"}, ClearedBy: []string{"rev2", "bob"}}, SignedOff},
		{finding.Meta{Status: "verification", Reviewers: []string{"bob"}, ClearedBy: []string{"bob", "dora"}}, SignedOff},
		// a director's sign-off alone, with no reviewer assigned, is not it
		{finding.Meta{Status: "verification", ClearedBy: []string{"dora"}}, "verification"},
		{finding.Meta{Status: "complete", Reviewers: []string{"bob"}, ClearedBy: []string{"bob"}}, "complete"},
		{finding.Meta{Status: Withdrawn, Reviewers: []string{"bob"}, ClearedBy: []string{"bob"}}, Withdrawn},
	} {
		if got := Shown(c.m); got != c.want {
			t.Errorf("Shown(%+v) = %q, want %q", c.m, got, c.want)
		}
	}
	if !slices.Equal(ShownSteps, []string{"draft", "verification", SignedOff, "complete", "reported"}) {
		t.Fatalf("steps %v", ShownSteps)
	}
	if ShownAll[len(ShownAll)-1] != Withdrawn || len(ShownAll) != 6 {
		t.Fatalf("all %v", ShownAll)
	}
	if StatusLabel(SignedOff) != "signed off" || StatusLabel("draft") != "draft" {
		t.Fatal("labels")
	}
	// sentence case for filters and legends, safe on an empty key
	for in, want := range map[string]string{SignedOff: "Signed off", "draft": "Draft", "critical": "Critical", "": ""} {
		if got := StatusTitle(in); got != want {
			t.Errorf("StatusTitle(%q) = %q, want %q", in, got, want)
		}
	}
	// the stored statuses are unchanged
	if slices.Contains(Statuses, SignedOff) || slices.Contains(AllStatuses, SignedOff) {
		t.Fatal("signed off is not a stored status")
	}
}
