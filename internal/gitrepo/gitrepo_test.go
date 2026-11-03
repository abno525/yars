package gitrepo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func lastCommit(t *testing.T, dir string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "log", "-1", "--format=%an|%ae|%s").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestCommitAuthor(t *testing.T) {
	dir := t.TempDir()
	r, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Commit([]string{"a.txt"}, "msg", Author{"alice", "alice@yars.local"}); err != nil {
		t.Fatal(err)
	}
	if got := lastCommit(t, dir); got != "alice|alice@yars.local|msg" {
		t.Fatalf("got %q", got)
	}
}

func TestHeadChanges(t *testing.T) {
	dir := t.TempDir()
	r, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	h0, err := r.Head()
	if err != nil || h0 != "" {
		t.Fatalf("empty head = %q, %v", h0, err)
	}
	a := Author{"a", "a@x"}
	os.WriteFile(filepath.Join(dir, "a"), []byte("1"), 0o644)
	if err := r.Commit([]string{"a"}, "1", a); err != nil {
		t.Fatal(err)
	}
	h1, _ := r.Head()
	os.WriteFile(filepath.Join(dir, "a"), []byte("2"), 0o644)
	if err := r.Commit([]string{"a"}, "2", a); err != nil {
		t.Fatal(err)
	}
	h2, _ := r.Head()
	if h1 == "" || h1 == h2 {
		t.Fatalf("h1=%q h2=%q", h1, h2)
	}
}

func TestOpenNonRepo(t *testing.T) {
	if _, err := Open(t.TempDir()); err == nil {
		t.Fatal("expected error")
	}
}
