package gitrepo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Sizes, Blobs and Init run git within the time limit, as every other
// command: a git that hangs ends as "timed out", not as a wait without end.
func TestBatchReadsAndInitTimeOut(t *testing.T) {
	dir := t.TempDir()
	r, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644)
	if err := r.Commit([]string{"a.txt"}, "first", Author{"alice", "alice@yars.local"}); err != nil {
		t.Fatal(err)
	}
	// the real git still answers both
	if ns, err := r.Sizes([]string{"HEAD:a.txt", "HEAD:none"}); err != nil || len(ns) != 2 || ns[0] != 1 || ns[1] != -1 {
		t.Fatalf("Sizes = %v, %v", ns, err)
	}
	if bs, err := r.Blobs([]string{"HEAD:a.txt", "HEAD:none"}); err != nil || len(bs) != 2 || string(bs[0]) != "a" || bs[1] != nil {
		t.Fatalf("Blobs = %q, %v", bs, err)
	}

	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\nsleep 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	old := Timeout
	Timeout = 200 * time.Millisecond
	t.Cleanup(func() { Timeout = old })

	want := func(what string, err error, text string) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: no error", what)
			return
		}
		if !strings.Contains(err.Error(), text) {
			t.Errorf("%s: the error lacks %q: %v", what, text, err)
		}
	}
	_, err = r.Sizes([]string{"HEAD:a.txt"})
	want("Sizes", err, "git cat-file --batch-check=%(objectsize): timed out after 200ms")
	_, err = r.Blobs([]string{"HEAD:a.txt"})
	want("Blobs", err, "git cat-file --batch: timed out after 200ms")
	_, err = Init(filepath.Join(t.TempDir(), "new"))
	want("Init", err, "git init: timed out after 200ms")
}
