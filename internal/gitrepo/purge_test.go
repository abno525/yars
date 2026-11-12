package gitrepo

import (
	"errors"
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

// git runs a command that needs an identity (merge) in dir.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	return gitOut(t, dir, append([]string{"-c", "user.name=t", "-c", "user.email=t@yars.local"}, args...)...)
}

// D28: a version a merge left out (-s ours) and one a merge made (a
// conflict resolved with a new file) are listed too.
func TestBlobsOfMergedVersions(t *testing.T) {
	r, dir, blobA, blobB := history(t)
	main, err := r.CurrentBranch()
	if err != nil {
		t.Fatal(err)
	}
	put := func(body, msg string) string {
		t.Helper()
		os.WriteFile(filepath.Join(dir, "a.png"), []byte(body), 0o644)
		git(t, dir, "add", "a.png")
		git(t, dir, "commit", "-q", "-m", msg)
		return gitOut(t, dir, "rev-parse", "HEAD:a.png")
	}
	git(t, dir, "checkout", "-q", "-b", "side", "HEAD~1")
	blobC := put("C", "side")
	git(t, dir, "checkout", "-q", main)
	git(t, dir, "merge", "-q", "-s", "ours", "-m", "keep ours", "side")
	git(t, dir, "checkout", "-q", "-b", "side2", "HEAD")
	blobD := put("D", "side2")
	git(t, dir, "checkout", "-q", main)
	put("E", "main")
	exec.Command("git", "-C", dir, "-c", "user.name=t", "-c", "user.email=t@yars.local", "merge", "-q", "side2").Run() // conflicts
	blobF := put("F", "resolved")
	got, err := r.BlobsOf("a.png")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{blobA, blobB, blobC, blobD, blobF} {
		if !slices.Contains(got, want) {
			t.Fatalf("blobs %v lack %s", got, want)
		}
	}
	if b, err := r.BlobAt("HEAD", "a.png"); err != nil || b != blobF {
		t.Fatalf("blob at HEAD %s %v, want %s", b, err, blobF)
	}
	if b, err := r.BlobAt("HEAD", "none.png"); err != nil || b != "" {
		t.Fatalf("a path HEAD lacks: %q %v", b, err)
	}
}

// D28: the same bytes under another path keep the old version in history:
// the drop says where, before anything is removed.
func TestDropOldBlobsRefusesWhileElsewhere(t *testing.T) {
	r, dir, blobA, blobB := history(t)
	if err := os.WriteFile(filepath.Join(dir, "copy.png"), []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Commit([]string{"copy.png"}, "copy", Author{"alice", "alice@yars.local"}); err != nil {
		t.Fatal(err)
	}
	err := r.DropOldBlobs("a.png", blobB)
	if err == nil || !strings.Contains(err.Error(), "copy.png") {
		t.Fatalf("drop with a copy elsewhere: %v", err)
	}
	if exec.Command("git", "-C", dir, "cat-file", "-e", blobA).Run() != nil {
		t.Fatal("objects were removed before the refusal")
	}
}

// D28: keep must be the current version: a drop that would change HEAD's
// files is refused.
func TestDropOldBlobsKeepsHeadTree(t *testing.T) {
	r, _, blobA, _ := history(t)
	if err := r.DropOldBlobs("a.png", blobA); err == nil || !strings.Contains(err.Error(), "current files") {
		t.Fatalf("a drop of the current version: %v", err)
	}
}

// D28: once gc has started there is no way back; its failure says so.
func TestDropOldBlobsCleanupFailure(t *testing.T) {
	r, dir, blobA, blobB := history(t)
	if err := os.WriteFile(filepath.Join(dir, ".git", "objects", "info", "commit-graph.lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err := r.DropOldBlobs("a.png", blobB)
	if !errors.Is(err, ErrPurgeCleanup) {
		t.Fatalf("gc failure: %v", err)
	}
	if exec.Command("git", "-C", dir, "cat-file", "-e", blobA).Run() == nil {
		t.Fatal("the old blob is still there")
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
