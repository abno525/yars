package gitserve

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
)

func put(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// cleanFixture is a main repository with the engagement acme, which holds
// one committed finding.
func cleanFixture(t *testing.T) (main *gitrepo.Repo, eng string) {
	t.Helper()
	main, err := gitrepo.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	eng = filepath.Join(main.Dir, "engagements", "acme")
	er, err := gitrepo.Init(eng)
	if err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(eng, "engagement.yaml"), "id: acme\n")
	put(t, filepath.Join(eng, "findings", "F-001-x", "finding.md"), "---\nid: F-001\n---\n\n## Description\n\nreal\n")
	if err := er.Commit([]string{"engagement.yaml", "findings"}, "start", gitrepo.Author{Name: "a", Email: "a@x"}); err != nil {
		t.Fatal(err)
	}
	return main, eng
}

// A stop between a file's write and its commit leaves files no commit
// holds, and every page would read them as real. The start removes them
// from each engagement's findings folder, also when a git ignore rule of
// the service account matches them, and nothing else: not the main
// repository's own untracked files, not what is committed.
func TestCleanLeftovers(t *testing.T) {
	main, eng := cleanFixture(t)
	excl := filepath.Join(t.TempDir(), "ignore")
	put(t, excl, "*.png\n")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "core.excludesFile")
	t.Setenv("GIT_CONFIG_VALUE_0", excl)

	tracked := filepath.Join(eng, "findings", "F-001-x", "finding.md")
	before, _ := os.ReadFile(tracked)
	gone := []string{
		filepath.Join(eng, "findings", "F-009-y", "finding.md"),
		filepath.Join(eng, "findings", "F-001-x", "attachments", "new.png"),
	}
	kept := []string{
		filepath.Join(main.Dir, ".yars", "yars.db"),
		filepath.Join(main.Dir, "secret.key"),
		filepath.Join(main.Dir, "findings", "stray.md"), // the main repository is never cleaned
		filepath.Join(eng, "notes.txt"),                 // nor an engagement outside findings/
	}
	for _, p := range append(append([]string{}, gone...), kept...) {
		put(t, p, "x")
	}
	got, err := CleanLeftovers(main)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Eng != "acme" || got[0].N != 2 {
		t.Fatalf("cleaned %+v", got)
	}
	for _, p := range gone {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s is still there", p)
		}
	}
	for _, p := range kept {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was removed", p)
		}
	}
	if after, _ := os.ReadFile(tracked); string(after) != string(before) {
		t.Fatalf("the committed finding changed:\n%s", after)
	}
	out, _ := exec.Command("git", "-C", eng, "status", "--porcelain", "--ignored", "--", "findings").Output()
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("findings not clean:\n%s", out)
	}
	// nothing left: nothing reported
	if got, err := CleanLeftovers(main); err != nil || len(got) != 0 {
		t.Fatalf("second run %+v %v", got, err)
	}
}

// An engagement repository a stop left without a commit (its files staged
// or not) does not stop the start, and nothing in it is removed: none of it
// is committed, so there is no telling the real from the leftover.
func TestStartStepsLeaveUnbornRepo(t *testing.T) {
	main, _ := cleanFixture(t)
	fresh := filepath.Join(main.Dir, "engagements", "fresh")
	if _, err := gitrepo.Init(fresh); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(fresh, "findings", "F-001-x", "finding.md")
	loose := filepath.Join(fresh, "findings", "F-002-y", "finding.md")
	put(t, filepath.Join(fresh, "engagement.yaml"), "id: fresh\n")
	put(t, staged, "x")
	put(t, loose, "x")
	if out, err := exec.Command("git", "-C", fresh, "add", "engagement.yaml", "findings/F-001-x").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if err := RestoreTrees(main); err != nil {
		t.Fatalf("the start stops at a repository without a commit: %v", err)
	}
	got, err := CleanLeftovers(main)
	if err != nil || len(got) != 0 {
		t.Fatalf("cleaned %+v %v", got, err)
	}
	for _, p := range []string{staged, loose} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was removed", p)
		}
	}
}
