package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
)

// commandNames are the commands of the dispatch (run). The usage text names
// each, and none of them is answered as unknown.
var commandNames = []string{"version", "help", "init", "use", "serve", "status", "users", "useradd", "admin", "disable", "enable", "passwd", "role",
	"userdel", "unlock", "token", "migrate", "backup", "restore", "lint", "hook", "export", "mcp", "seed"}

// keepUmask gives the process its umask back when the test ends: run sets
// the private one for a server-side command and, as main, never undoes it.
func keepUmask(t *testing.T) {
	t.Helper()
	restore := privateUmask()
	restore()
	t.Cleanup(restore)
}

// yars runs a command line as main does and returns the exit code and the
// two streams.
func yars(t *testing.T, in string, args ...string) (code int, out, errOut string) {
	t.Helper()
	keepUmask(t)
	var o, e bytes.Buffer
	code = run(args, strings.NewReader(in), &o, &e)
	return code, o.String(), e.String()
}

// nowhere runs a test in an empty folder with no data folder set, and
// returns a check that nothing was written there.
func nowhere(t *testing.T) (unchanged func()) {
	t.Helper()
	keepUmask(t)
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("YARS_DATA", "")
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	return func() {
		t.Helper()
		if ents, err := os.ReadDir(dir); err != nil || len(ents) != 0 {
			t.Fatalf("the folder is not empty any more: %v %v", ents, err)
		}
	}
}

// yars help, -h and --help print the usage on stdout and exit 0, with no
// data folder and without making one.
func TestHelp(t *testing.T) {
	unchanged := nowhere(t)
	for _, arg := range []string{"help", "-h", "--help", "-help"} {
		var out, errOut bytes.Buffer
		if code := run([]string{arg}, strings.NewReader(""), &out, &errOut); code != 0 {
			t.Fatalf("yars %s: exit %d\n%s", arg, code, errOut.String())
		}
		if out.String() != usageText || !strings.HasPrefix(out.String(), "usage") || errOut.Len() != 0 {
			t.Fatalf("yars %s: stdout %q, stderr %q", arg, out.String(), errOut.String())
		}
	}
	unchanged()
}

// The usage text names every command, on a line of its own.
func TestUsageNamesEveryCommand(t *testing.T) {
	for _, name := range commandNames {
		if !strings.Contains(usageText, "\n  yars "+name+" ") && !strings.Contains(usageText, "\n  yars "+name+"\n") {
			t.Errorf("the usage text has no line for yars %s", name)
		}
	}
	if !strings.HasSuffix(usageText, "\n") || strings.HasSuffix(usageText, "\n\n") {
		t.Error("the usage text does not end with one line break")
	}
}

// yars --version and -version print what yars version prints.
func TestVersionFlag(t *testing.T) {
	unchanged := nowhere(t)
	old := version
	defer func() { version = old }()
	version = "v1.0.0"
	want := "yars v1.0.0 (schema " + strconv.Itoa(db.SchemaVersion) + ", " + runtime.Version() + ")\n"
	for _, arg := range []string{"version", "--version", "-version"} {
		var out, errOut bytes.Buffer
		if code := run([]string{arg}, strings.NewReader(""), &out, &errOut); code != 0 || out.String() != want || errOut.Len() != 0 {
			t.Fatalf("yars %s: exit %d, stdout %q, stderr %q", arg, code, out.String(), errOut.String())
		}
	}
	unchanged()
}

// A command line without a command, or with one yars does not know, is a
// mistake: the usage on stderr, exit 2, and the unknown word named.
func TestNoCommandAndUnknownCommand(t *testing.T) {
	unchanged := nowhere(t)
	var out, errOut bytes.Buffer
	if code := run(nil, strings.NewReader(""), &out, &errOut); code != 2 || out.Len() != 0 || errOut.String() != usageText {
		t.Fatalf("no command: exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
	errOut.Reset()
	if code := run([]string{"nope\x1b[31m"}, strings.NewReader(""), &out, &errOut); code != 2 || out.Len() != 0 {
		t.Fatalf("unknown: exit %d, stdout %q", code, out.String())
	}
	if got := errOut.String(); got != `yars: unknown command "nope\x1b[31m"`+"\n"+usageText {
		t.Fatalf("unknown: stderr %q", got)
	}
	unchanged()
}

// yars <command> -h is a question, not a failure: exit 0 and no "help
// requested" line.
func TestCommandHelpFlag(t *testing.T) {
	unchanged := nowhere(t)
	for _, line := range []string{"useradd -h", "admin --help", "token add -h", "export -h", "lint -h", "serve -h", "init -h", "status -h"} {
		var out, errOut bytes.Buffer
		code := run(strings.Fields(line), strings.NewReader(""), &out, &errOut)
		if code != 0 || strings.Contains(out.String()+errOut.String(), "help requested") || strings.Contains(errOut.String(), "yars:") {
			t.Errorf("yars %s: exit %d, stdout %q, stderr %q", line, code, out.String(), errOut.String())
		}
	}
	unchanged()
}

// Every command of the dispatch answers -h and --help with exit 0 and no
// "yars:" line, the commands without flags of their own too, and writes
// nothing. Those print their usage line on stdout.
func TestEveryCommandHelpFlag(t *testing.T) {
	unchanged := nowhere(t)
	lines := []string{"token add", "token list", "token revoke", "hook install"}
	for _, name := range commandNames {
		if name != "help" {
			lines = append(lines, name)
		}
	}
	usage := map[string]string{
		"use":     "usage: yars use [<dir>]\n",
		"version": "usage: yars version\n",
		"hook":    hookUsage + "\n",
	}
	for _, line := range lines {
		for _, h := range []string{"-h", "--help"} {
			var out, errOut bytes.Buffer
			code := run(append(strings.Fields(line), h), strings.NewReader(""), &out, &errOut)
			if code != 0 || strings.Contains(out.String()+errOut.String(), "help requested") || strings.Contains(errOut.String(), "yars:") {
				t.Errorf("yars %s %s: exit %d, stdout %q, stderr %q", line, h, code, out.String(), errOut.String())
			}
			if want, ok := usage[line]; ok && (out.String() != want || errOut.Len() != 0) {
				t.Errorf("yars %s %s: stdout %q, stderr %q, want %q on stdout", line, h, out.String(), errOut.String(), want)
			}
			if line == "token" && !strings.HasPrefix(out.String(), tokenUsage+"\n") {
				t.Errorf("yars token %s: stdout %q", h, out.String())
			}
		}
	}
	unchanged()
}

// yars token -h, and a token command yars does not know, are answered before
// the data folder is opened: no database is made there.
func TestTokenHelpMakesNoDatabase(t *testing.T) {
	keepUmask(t)
	dir := t.TempDir()
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	old, _ := filepath.Glob(db.Path(dir) + "*")
	for _, p := range old {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	for arg, want := range map[string]int{"-h": 0, "--help": 0, "nope": 2} {
		var out, errOut bytes.Buffer
		if code := run([]string{"token", arg, "--data", dir}, strings.NewReader(""), &out, &errOut); code != want {
			t.Errorf("yars token %s: exit %d, want %d\n%s%s", arg, code, want, out.String(), errOut.String())
		}
		if made, _ := filepath.Glob(db.Path(dir) + "*"); len(made) != 0 {
			t.Fatalf("yars token %s made %v", arg, made)
		}
	}
}

// No command of the dispatch is answered as an unknown one. Each is run
// with a flag it does not have, so it stops at its own flags.
func TestEveryNamedCommandIsDispatched(t *testing.T) {
	unchanged := nowhere(t)
	for _, name := range commandNames {
		if name == "hook" { // reads a push from stdin; yars hook install is below
			continue
		}
		var out, errOut bytes.Buffer
		run([]string{name, "--zq-no-such-flag"}, strings.NewReader(""), &out, &errOut)
		if strings.Contains(errOut.String(), "unknown command") {
			t.Errorf("yars %s is not a command of the dispatch: %s", name, errOut.String())
		}
	}
	var out, errOut bytes.Buffer
	if run([]string{"hook", "install", "--zq-no-such-flag"}, strings.NewReader(""), &out, &errOut); strings.Contains(errOut.String(), "unknown command") {
		t.Errorf("yars hook install: %s", errOut.String())
	}
	unchanged()
}
