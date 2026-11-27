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

// reftableGit skips the test when this git cannot make a reftable
// repository (before 2.45).
func reftableGit(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("git", "init", "-q", "--ref-format=reftable", t.TempDir()).CombinedOutput(); err != nil {
		t.Skipf("git has no reftable: %v %s", err, out)
	}
}

// A service account whose git config asks for reftable still gets a
// repository ReadHead can read: Init makes the files format.
func TestInitMakesFilesRefFormat(t *testing.T) {
	reftableGit(t)
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "init.defaultRefFormat")
	t.Setenv("GIT_CONFIG_VALUE_0", "reftable")
	dir := t.TempDir()
	r, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "a"), []byte("1"), 0o644)
	if err := r.Commit([]string{"a"}, "1", Author{"a", "a@x"}); err != nil {
		t.Fatal(err)
	}
	want, _ := r.Head()
	n := Spawned()
	got, err := ReadHead(dir)
	if err != nil || got != want || got == "" {
		t.Fatalf("ReadHead %q %v, want %q", got, err, want)
	}
	if Spawned() != n {
		t.Fatal("ReadHead started git in a repository Init made")
	}
}

// A repository that is reftable already (made before, or restored from a
// backup) is read by asking git: ReadHead agrees with Head, with and
// without a commit.
func TestReadHeadReftable(t *testing.T) {
	reftableGit(t)
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", "-q", "-b", "main", "--ref-format=reftable", dir).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	r, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ReadHead(dir); err != nil || got != "" {
		t.Fatalf("no commit yet: ReadHead %q %v", got, err)
	}
	os.WriteFile(filepath.Join(dir, "a"), []byte("1"), 0o644)
	if err := r.Commit([]string{"a"}, "1", Author{"a", "a@x"}); err != nil {
		t.Fatal(err)
	}
	want, _ := r.Head()
	if got, err := ReadHead(dir); err != nil || got != want || got == "" {
		t.Fatalf("ReadHead %q %v, want %q", got, err, want)
	}
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
