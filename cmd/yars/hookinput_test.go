package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"yars/internal/config"
)

// The pre-receive hook refuses a push whose input it cannot read whole: a
// line that is not "<old> <new> <ref>", a read error, a line too long to
// scan. Skipping them would let the updates on them through unchecked
// (backlog, M6).
func TestHookInputFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if err := openDB(t, dir).AddUser(config.User{Username: "dora", Role: "director"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REMOTE_USER", "dora")
	zero := strings.Repeat("0", 40)
	for name, in := range map[string]io.Reader{
		"a malformed line": strings.NewReader("not an update\n"),
		"a fourth field":   strings.NewReader(zero + " " + zero + " refs/heads/main extra\n"),
		"a read error":     io.MultiReader(strings.NewReader(zero+" "), iotest.ErrReader(errors.New("pipe broke"))),
		"a line too long":  strings.NewReader(strings.Repeat("x", 1<<20) + "\n"),
	} {
		var out bytes.Buffer
		if code := cmdHook([]string{"pre-receive", "--data", dir}, in, &out); code != 1 || !strings.Contains(out.String(), "unreadable hook input") {
			t.Errorf("%s: code %d: %s", name, code, out.String())
		}
	}
	// well-formed input still gets to the checks (here: no such branch)
	var out bytes.Buffer
	if code := cmdHook([]string{"pre-receive", "--data", dir}, strings.NewReader(zero+" "+strings.Repeat("a", 40)+" refs/heads/other\n"), &out); code != 1 || !strings.Contains(out.String(), "only refs/heads/main can be pushed") {
		t.Errorf("a good line: code %d: %s", code, out.String())
	}
}
