package store

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Finding folders are listed by their number, not as strings: F-999 before
// F-1000, a pushed F-7 before F-012. A folder outside the F-<n> scheme comes
// after them.
func TestFindingsListedByNumber(t *testing.T) {
	s, dir := withEngagement(t)
	names := []string{"F-1000-b", "F-999-a", "notes", "F-012-d", "F-7-c", "F-7"}
	for _, n := range names {
		p := filepath.Join(dir, "engagements", eng, "findings", n)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "finding.md"), []byte("---\nid: "+n+"\ntitle: T\n---\n\n## Description\n\nx\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"F-7", "F-7-c", "F-012-d", "F-999-a", "F-1000-b", "notes"}
	dirs, err := s.FindingDirs(eng)
	if err != nil || !slices.Equal(dirs, want) {
		t.Fatalf("FindingDirs %v %v, want %v", dirs, err, want)
	}
	refs, err := s.ListFindings(eng)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range refs {
		got = append(got, r.Dir)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ListFindings %v, want %v", got, want)
	}
}

func TestCompareIDs(t *testing.T) {
	// in order: each is before every one after it
	order := []string{"F-1", "F-002", "F-2", "F-2-b", "F-9", "F-10", "F-999", "F-1000", "F-99999999999999999999", "F-100000000000000000000", "A", "F-", "F-1x", "G"}
	for i, a := range order {
		for j, b := range order {
			c := CompareIDs(a, b)
			if (i < j && c >= 0) || (i > j && c <= 0) || (i == j && c != 0) {
				t.Errorf("CompareIDs(%q, %q) = %d", a, b, c)
			}
		}
	}
}
