package gitrepo

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// The history is read with NUL between its fields: an author name or a
// subject with the control characters the old format split on (0x1e, 0x1f)
// neither drops a commit nor makes a second one, and a file name is taken
// as git has it (a quote, a space at its end), also across a rename.
func TestLogTakesAnyNameAndSubject(t *testing.T) {
	dir := t.TempDir()
	r, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, text string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(a Author, msg string, files ...string) string {
		t.Helper()
		if err := r.Commit(files, msg, a); err != nil {
			t.Fatal(err)
		}
		h, err := r.Head()
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	alice := Author{"alice", "alice@yars.local"}
	const (
		oddName    = "a\x1fb"
		oddSubject = "one\x1etwo\x1fx\x1fy\x1fz"
		quoted     = `d/q"uote.txt`
		spaced     = "d/trail "
	)
	long := "line one\nline two is long enough for git to see the same file after a rename\nline three\nline four\n"
	write("d/a.txt", long)
	h1 := commit(Author{oddName, "odd@yars.local"}, "first", "d/a.txt")
	write("d/a.txt", long+"more\n")
	write(quoted, "q")
	h2 := commit(alice, oddSubject, "d/a.txt", quoted)
	write(spaced, "s")
	h3 := commit(alice, "third", spaced)
	// a rename, made with git itself
	for _, args := range [][]string{{"mv", "d/a.txt", "d/b.txt"}, {"-c", "user.name=alice", "-c", "user.email=alice@yars.local", "-c", "commit.gpgsign=false", "commit", "-q", "-m", "rename"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	h4, _ := r.Head()

	es, err := r.LogDir("d")
	if err != nil {
		t.Fatal(err)
	}
	want := []LogEntry{
		{Hash: h4, Author: "alice", Subject: "rename", Paths: []string{"d/b.txt"}},
		{Hash: h3, Author: "alice", Subject: "third", Paths: []string{spaced}},
		{Hash: h2, Author: "alice", Subject: oddSubject, Paths: []string{"d/a.txt", quoted}},
		{Hash: h1, Author: oddName, Subject: "first", Paths: []string{"d/a.txt"}},
	}
	check := func(what string, es, want []LogEntry) {
		t.Helper()
		if len(es) != len(want) {
			t.Fatalf("%s: %d entries, want %d: %+v", what, len(es), len(want), es)
		}
		for i, w := range want {
			e := es[i]
			if e.Hash != w.Hash || e.Author != w.Author || e.Subject != w.Subject || !slices.Equal(e.Paths, w.Paths) || e.Path != w.Paths[0] || e.Time.IsZero() {
				t.Errorf("%s entry %d: %+v\nwant %+v", what, i, e, w)
			}
		}
	}
	check("LogDir", es, want)

	// one file, followed across its rename: the old path in the old commits
	es, err = r.LogFollow("d/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	check("LogFollow", es, []LogEntry{
		{Hash: h4, Author: "alice", Subject: "rename", Paths: []string{"d/b.txt"}},
		{Hash: h2, Author: "alice", Subject: oddSubject, Paths: []string{"d/a.txt"}},
		{Hash: h1, Author: oddName, Subject: "first", Paths: []string{"d/a.txt"}},
	})

	// a commit that touched nothing under the path is not listed, and one
	// without files does not shift the entries after it
	if out, err := exec.Command("git", "-C", dir, "-c", "user.name=alice", "-c", "user.email=alice@yars.local", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "empty").CombinedOutput(); err != nil {
		t.Fatalf("empty commit: %v %s", err, out)
	}
	if es, err = r.LogDir("d"); err != nil {
		t.Fatal(err)
	}
	check("LogDir after an empty commit", es, want)
}

// parseLog reads what git log -z --name-only writes for logFormat: a commit
// without names between two with names, and nothing that is no commit.
func TestParseLogShape(t *testing.T) {
	h := func(c string) string { return c + "0123456789abcdef0123456789abcdef0123456" }
	out := "\x00" + h("a") + "\x001700000003\x00al\x00s3\x00\x00\nx.txt\x00\ny.txt\x00" +
		"\x00" + h("b") + "\x001700000002\x00al\x00\x00\x00" +
		"\x00" + h("c") + "\x001700000001\x00al\x00s1\x00\x00\n" + h("d") + "\x00"
	es := parseLog(out)
	if len(es) != 3 {
		t.Fatalf("%d entries: %+v", len(es), es)
	}
	if !slices.Equal(es[0].Paths, []string{"x.txt", "\ny.txt"}) || es[0].Subject != "s3" || es[0].Time.Unix() != 1700000003 {
		t.Errorf("first %+v", es[0])
	}
	if es[1].Hash != h("b") || es[1].Subject != "" || len(es[1].Paths) != 0 || es[1].Path != "" {
		t.Errorf("second %+v", es[1])
	}
	// a file named like a commit id is a file
	if es[2].Hash != h("c") || !slices.Equal(es[2].Paths, []string{h("d")}) {
		t.Errorf("third %+v", es[2])
	}
	for _, bad := range []string{"", "junk", "\x00not-hex\x001\x00a\x00s\x00\x00", "\x00" + h("a") + "\x001\x00a\x00s"} {
		if es := parseLog(bad); len(es) != 0 {
			t.Errorf("%q: %+v", bad, es)
		}
	}
}
