package store

import (
	"os"
	"path/filepath"
	"testing"
)

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
