package gitrepo

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// history makes a repository where a.png was A, then B (with another
// commit between), and returns it with the blob ids of A and B.
func history(t *testing.T) (r *Repo, dir, blobA, blobB string) {
	t.Helper()
	dir = t.TempDir()
	r, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	commit := func(name, body, msg string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := r.Commit([]string{name}, msg, Author{"alice", "alice@yars.local"}); err != nil {
			t.Fatal(err)
		}
	}
	commit("a.png", "A", "first")
	blobA = gitOut(t, dir, "rev-parse", "HEAD:a.png")
	commit("note.txt", "n", "second")
	commit("a.png", "B", "third")
	blobB = gitOut(t, dir, "rev-parse", "HEAD:a.png")
	return r, dir, blobA, blobB
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// D28: the blobs a path has had, newest first.
func TestBlobsOf(t *testing.T) {
	r, _, blobA, blobB := history(t)
	got, err := r.BlobsOf("a.png")
	if err != nil || !slices.Equal(got, []string{blobB, blobA}) {
		t.Fatalf("blobs %v %v, want %v %v", got, err, blobB, blobA)
	}
	if got, _ := r.BlobsOf("note.txt"); len(got) != 1 {
		t.Fatalf("note blobs %v", got)
	}
}

// D28: every version of a path but keep goes from history; the commits and
// the work tree stay.
func TestDropOldBlobs(t *testing.T) {
	r, dir, blobA, blobB := history(t)
	before := gitOut(t, dir, "log", "--format=%s")
	if err := r.DropOldBlobs("a.png", blobB); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("git", "-C", dir, "cat-file", "-e", blobA).Run(); err == nil {
		t.Fatal("the old blob is still in the repository")
	}
	if after := gitOut(t, dir, "log", "--format=%s"); after != before {
		t.Fatalf("subjects %q, were %q", after, before)
	}
	if st := gitOut(t, dir, "status", "--porcelain"); st != "" {
		t.Fatalf("work tree changed: %q", st)
	}
	if got := gitOut(t, dir, "rev-parse", "HEAD:a.png"); got != blobB {
		t.Fatalf("current blob %s, want %s", got, blobB)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "a.png")); string(b) != "B" {
		t.Fatalf("file %q", b)
	}
	if refs := gitOut(t, dir, "for-each-ref", "refs/original"); refs != "" {
		t.Fatalf("backup refs left: %s", refs)
	}
}
