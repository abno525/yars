package gitrepo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A failed git command's error names the command and its paths, never the
// commit message: the message holds what a person typed (an attachment's
// name, a section, a template), and the error is logged.
func TestErrorLeavesOutTheCommitMessage(t *testing.T) {
	const m = "zqmessage7f3kq"
	dir := t.TempDir()
	r, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	a := Author{"alice", "alice@yars.local"}
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644)
	if err := r.Commit([]string{"a.txt"}, "first", a); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "hooks", "pre-commit"), []byte("#!/bin/sh\necho refused >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	check := func(what string, err error, wants ...string) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s: no error", what)
		}
		if strings.Contains(err.Error(), m) {
			t.Errorf("%s: the error holds the message: %v", what, err)
		}
		for _, want := range wants {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the error lacks %q: %v", what, want, err)
			}
		}
	}
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("b"), 0o644)
	check("commit", r.Commit([]string{"b.txt"}, "F-001: attach "+m+".png", a), "git commit -q --only -- b.txt: ", "refused")
	r.Unstage([]string{"b.txt"})
	check("untrack", r.Untrack("a.txt", "untrack "+m, a), "git commit -q: ", "refused")

	// a command that passes its time limit
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nsleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	old := Timeout
	Timeout = 200 * time.Millisecond
	t.Cleanup(func() { Timeout = old })
	_, err = r.run(nil, "commit", "-q", "--only", "-m", "report: edit "+m, "--", "b.txt")
	check("timeout", err, "git commit -q --only -- b.txt: timed out after 200ms")
}
