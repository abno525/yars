package gitrepo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// Committing a nested repository's folder records it as a submodule
// pointer (gitlink) at the nested repo's HEAD.
func TestCommitNestedRepoIsGitlink(t *testing.T) {
	main, _ := Init(t.TempDir())
	sub, err := Init(filepath.Join(main.Dir, "engagements", "acme"))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(sub.Dir, "engagement.yaml"), []byte("name: A\n"), 0o644)
	if err := sub.Commit([]string{"engagement.yaml"}, "create", Author{"a", "a@a"}); err != nil {
		t.Fatal(err)
	}
	if err := main.Commit([]string{"engagements/acme"}, "add acme", Author{"a", "a@a"}); err != nil {
		t.Fatal(err)
	}
	head, _ := sub.Head()
	if got, _ := main.Gitlink("HEAD", "engagements/acme"); got != head {
		t.Fatalf("gitlink %q want %q", got, head)
	}
	out, _ := exec.Command("git", "-C", main.Dir, "ls-tree", "HEAD", "engagements/acme").Output()
	if !strings.HasPrefix(string(out), "160000 commit "+head) {
		t.Fatalf("ls-tree %q", out)
	}
	if got, _ := main.Gitlink("HEAD", "engagements/none"); got != "" {
		t.Fatalf("missing gitlink %q", got)
	}
}

// A moved or removed submodule pointer is a change even when .gitmodules
// says ignore = all (as every engagement's entry does).
func TestChangedFilesSeesIgnoredSubmodules(t *testing.T) {
	main, _ := Init(t.TempDir())
	sub, _ := Init(filepath.Join(main.Dir, "engagements", "acme"))
	a := Author{"a", "a@a"}
	os.WriteFile(filepath.Join(sub.Dir, "engagement.yaml"), []byte("name: A\n"), 0o644)
	sub.Commit([]string{"engagement.yaml"}, "1", a)
	os.WriteFile(filepath.Join(main.Dir, ".gitmodules"), []byte("[submodule \"engagements/acme\"]\n\tpath = engagements/acme\n\turl = ../e/acme\n\tignore = all\n"), 0o644)
	if err := main.Commit([]string{".gitmodules", "engagements/acme"}, "add", a); err != nil {
		t.Fatal(err)
	}
	c1, _ := main.Head()
	os.WriteFile(filepath.Join(sub.Dir, "engagement.yaml"), []byte("name: B\n"), 0o644)
	sub.Commit([]string{"engagement.yaml"}, "2", a)
	h2, _ := sub.Head()
	git := func(args ...string) string {
		out, err := exec.Command("git", append([]string{"-C", main.Dir, "-c", "user.name=a", "-c", "user.email=a@a", "-c", "commit.gpgsign=false"}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("update-index", "--cacheinfo", "160000,"+h2+",engagements/acme")
	git("commit", "-q", "-m", "move")
	c2, _ := main.Head()
	git("rm", "-q", "--cached", "engagements/acme")
	git("commit", "-q", "-m", "drop")
	c3, _ := main.Head()
	for _, c := range [][2]string{{c1, c2}, {c2, c3}} {
		cs, err := main.ChangedFiles(c[0], c[1])
		if err != nil || len(cs) != 1 || cs[0].Path != "engagements/acme" {
			t.Errorf("%.8s..%.8s: %+v %v", c[0], c[1], cs, err)
		}
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

// A git command that hangs is stopped after Timeout, even when the process
// it started (a hook, here a sleep) still holds its output open.
func TestRunTimesOut(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	old := Timeout
	Timeout = 200 * time.Millisecond
	t.Cleanup(func() { Timeout = old })
	start := time.Now()
	err := (&Repo{Dir: t.TempDir()}).SetConfig("a.b", "c")
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("returned after %s", took)
	}
	if err == nil || !strings.Contains(err.Error(), "timed out after 200ms") {
		t.Fatalf("err %v", err)
	}
}

// Fsck reads every object, which takes long on a big repository: it is
// bounded by FsckTimeout, not by Timeout.
func TestFsckOutlivesTimeout(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nsleep 0.6\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	old := Timeout
	Timeout = 200 * time.Millisecond
	t.Cleanup(func() { Timeout = old })
	if err := (&Repo{Dir: t.TempDir()}).Fsck(); err != nil {
		t.Fatalf("fsck cut by the command timeout: %v", err)
	}
}

// Fsck passes a sound repository and fails one that lost an object.
func TestFsck(t *testing.T) {
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
	if err := r.Fsck(); err != nil {
		t.Fatalf("a sound repository: %v", err)
	}
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD:a.txt").Output()
	if err != nil {
		t.Fatal(err)
	}
	blob := strings.TrimSpace(string(out))
	if err := os.Remove(filepath.Join(dir, ".git", "objects", blob[:2], blob[2:])); err != nil {
		t.Fatal(err)
	}
	// git fsck says what is wrong on stdout: the error carries it
	if err := r.Fsck(); err == nil || !strings.Contains(err.Error(), "missing blob "+blob) {
		t.Fatalf("a repository without a blob: %v", err)
	}
}
