package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One commit goes into one repository: paths of two engagements, or of an
// engagement and the main repository, are refused (and put back) rather
// than routed by the first (backlog, M11).
func TestCommitRefusesTwoRepos(t *testing.T) {
	s, dir := newStore(t)
	for _, id := range []string{"acme", "other"} {
		if err := s.CreateEngagement(Engagement{ID: id, Name: id}, alice); err != nil {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]string{
		{"engagements/acme/a.txt", "engagements/other/b.txt"},
		{"engagements/acme/a.txt", ".yars/b.txt"},
	} {
		prev := map[string][]byte{}
		for _, rel := range pair {
			s.root.MkdirAll(filepath.Dir(rel), 0o755)
			s.writeFile(rel, []byte("new"))
			prev[rel] = nil
		}
		if err := s.commit(prev, "x", alice, ""); err == nil || !strings.Contains(err.Error(), "spans two repositories") {
			t.Fatalf("%v: %v", pair, err)
		}
		for _, rel := range pair {
			if _, err := os.Stat(filepath.Join(dir, rel)); err == nil {
				t.Fatalf("%v: %s stayed behind", pair, rel)
			}
		}
	}
}

// commit restores what it was given on every failure, also when the
// engagement's repository cannot be opened: the file written for it does
// not stay behind (backlog, M11).
func TestCommitRollsBackWithoutRepo(t *testing.T) {
	s, dir := newStore(t)
	rel := "engagements/ghost/findings/F-001-x/finding.md"
	if err := s.root.MkdirAll(filepath.Dir(rel), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.writeFile(rel, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if err := s.commit(map[string][]byte{rel: nil}, "x", alice, ""); err == nil {
		t.Fatal("committed into an engagement with no repository")
	}
	if _, err := os.Stat(filepath.Join(dir, rel)); err == nil {
		t.Fatal("the file stayed behind")
	}
}
