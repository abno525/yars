package gitrepo

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// ReadHead agrees with git rev-parse without starting a process: empty
// repo, loose ref, packed ref and detached HEAD.
func TestReadHeadNoProcess(t *testing.T) {
	dir := t.TempDir()
	r, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	check := func(what string) {
		t.Helper()
		want, _ := r.Head()
		n := Spawned()
		got, err := ReadHead(dir)
		if err != nil || got != want {
			t.Fatalf("%s: ReadHead %q %v, want %q", what, got, err, want)
		}
		if Spawned() != n {
			t.Fatalf("%s: ReadHead started git", what)
		}
	}
	check("empty")
	os.WriteFile(filepath.Join(dir, "a"), []byte("1"), 0o644)
	r.Commit([]string{"a"}, "1", Author{"a", "a@x"})
	check("loose")
	if out, err := exec.Command("git", "-C", dir, "pack-refs", "--all").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git", "refs", "heads", "main")); err == nil {
		t.Fatal("ref not packed")
	}
	check("packed")
	os.WriteFile(filepath.Join(dir, "a"), []byte("2"), 0o644)
	r.Commit([]string{"a"}, "2", Author{"a", "a@x"})
	check("loose after packed")
	if out, err := exec.Command("git", "-C", dir, "checkout", "-q", "--detach").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	check("detached")
}

// CommitGitlinks records exactly the given pointers, whatever the nested
// repos' HEADs are by now, and leaves nothing staged.
func TestCommitGitlinks(t *testing.T) {
	main, _ := Init(t.TempDir())
	a := Author{"a", "a@a"}
	sub, _ := Init(filepath.Join(main.Dir, "engagements", "acme"))
	os.WriteFile(filepath.Join(sub.Dir, "x"), []byte("1"), 0o644)
	sub.Commit([]string{"x"}, "1", a)
	h1, _ := sub.Head()
	main.Commit([]string{"engagements/acme"}, "add", a)
	os.WriteFile(filepath.Join(sub.Dir, "x"), []byte("2"), 0o644)
	sub.Commit([]string{"x"}, "2", a)
	h2, _ := sub.Head()
	os.WriteFile(filepath.Join(sub.Dir, "x"), []byte("3"), 0o644)
	sub.Commit([]string{"x"}, "3", a) // moved on past h2
	if err := main.CommitGitlinks(map[string]string{"engagements/acme": h2}, "sync", a); err != nil {
		t.Fatal(err)
	}
	if got, _ := main.Gitlink("HEAD", "engagements/acme"); got != h2 || got == h1 {
		t.Fatalf("gitlink %s want %s", got, h2)
	}
	out, _ := exec.Command("git", "-C", main.Dir, "diff", "--cached", "--name-only").Output()
	if len(out) != 0 {
		t.Fatalf("left staged: %s", out)
	}
}

func TestReadHeadNotARepo(t *testing.T) {
	if _, err := ReadHead(t.TempDir()); err == nil {
		t.Fatal("expected error")
	}
}

// Run counts every git process it starts.
func TestSpawnedCounts(t *testing.T) {
	r, _ := Init(t.TempDir())
	n := Spawned()
	r.Head()
	if Spawned() == n {
		t.Fatal("not counted")
	}
}

// Gitlinks lists every submodule pointer under a folder in one process.
func TestGitlinks(t *testing.T) {
	main, _ := Init(t.TempDir())
	a := Author{"a", "a@a"}
	heads := map[string]string{}
	for _, id := range []string{"acme", "beta"} {
		sub, _ := Init(filepath.Join(main.Dir, "engagements", id))
		os.WriteFile(filepath.Join(sub.Dir, "x"), []byte(id), 0o644)
		sub.Commit([]string{"x"}, "x", a)
		heads[id], _ = sub.Head()
		main.Commit([]string{"engagements/" + id}, "add", a)
	}
	n := Spawned()
	got, err := main.Gitlinks("HEAD", "engagements")
	if err != nil || len(got) != 2 || got["acme"] != heads["acme"] || got["beta"] != heads["beta"] {
		t.Fatalf("got %v %v want %v", got, err, heads)
	}
	if Spawned()-n != 1 {
		t.Fatalf("%d processes", Spawned()-n)
	}
	empty, _ := Init(t.TempDir())
	if got, err := empty.Gitlinks("HEAD", "engagements"); err != nil || len(got) != 0 {
		t.Fatalf("empty repo %v %v", got, err)
	}
}
