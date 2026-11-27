package main

import (
	"bytes"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/logs"
)

// gitSays makes the commands of this test read text as the output of `git
// version` (err: there is no git). The machine's own git plays no part in
// what the check decides.
func gitSays(t *testing.T, text string, err error) {
	t.Helper()
	old := gitVersionText
	t.Cleanup(func() { gitVersionText = old })
	gitVersionText = func() (string, error) { return text, err }
}

// yars serve does not start with a git older than 2.30, and says both
// versions. It stops before anything changes: the data folder's tree is not
// reset, and nothing listens.
func TestServeRefusesAnOldGit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	// an edit made in place, which a start undoes (it resets the tree)
	cfgPath := config.ConfigPath(dir)
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	edited := append(b, []byte("# zq edited in place\n")...)
	if err := os.WriteFile(cfgPath, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	// an address that is taken: a start that got that far fails there, and
	// the test never serves
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	for text, want := range map[string]string{
		"git version 2.20.1\n": "git 2.30 or later is needed; this is git 2.20",
		"git version 2.9.5\n":  "git 2.30 or later is needed; this is git 2.9",
	} {
		gitSays(t, text, nil)
		err = cmdServe([]string{"--data", dir, "--addr", ln.Addr().String()})
		if err == nil || err.Error() != want {
			t.Fatalf("%q: %v, want %q", text, err, want)
		}
	}
	gitSays(t, "", gitrepo.ErrNoGit)
	if err = cmdServe([]string{"--data", dir, "--addr", ln.Addr().String()}); err == nil || err.Error() != "git is not on the PATH" {
		t.Fatalf("no git: %v", err)
	}
	if now, _ := os.ReadFile(cfgPath); !bytes.Equal(now, edited) {
		t.Fatal("the refused start reset the data folder's tree")
	}
	if _, err := os.Lstat(statusSocket(dir)); err == nil {
		t.Fatal("the refused start left a status socket")
	}
}

// yars init and yars seed do not begin with an old git either: git init -b
// needs 2.28, and the folder would be half made.
func TestInitRefusesAnOldGit(t *testing.T) {
	gitSays(t, "git version 2.25.1\n", nil)
	dir := filepath.Join(t.TempDir(), "data")
	var out bytes.Buffer
	const want = "git 2.30 or later is needed; this is git 2.25"
	if err := cmdInitOut([]string{dir}, &out); err == nil || err.Error() != want {
		t.Fatalf("init: %v", err)
	}
	if err := cmdSeed([]string{"--data", dir}, &out); err == nil || err.Error() != want {
		t.Fatalf("seed: %v", err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("the folder was made")
	}
	// with a git that will do, the same command works
	gitSays(t, "git version 2.30.0\n", nil)
	if err := cmdInitOut([]string{dir}, &out); err != nil {
		t.Fatal(err)
	}
}

// A version that does not read stops nothing: the check says so, and the
// start writes one warn line, without what git printed.
func TestGitVersionThatDoesNotRead(t *testing.T) {
	for _, text := range []string{"git version zqweird7f3kq\n", "", "zqweird7f3kq"} {
		gitSays(t, text, nil)
		unread, err := checkGit()
		if err != nil || !unread {
			t.Fatalf("%q: unread %v, %v", text, unread, err)
		}
	}
	lg, rec := logs.NewRecorder()
	logGitUnread(lg)
	// the line names the release the check asks for
	l := rec.With("git: the version does not read; the start goes on (YARS needs git " + gitrepo.MinVersion() + " or later)")
	if len(l) != 1 || l[0].Level != slog.LevelWarn || strings.Contains(rec.Text(), "zqweird7f3kq") {
		t.Fatalf("log:\n%s", rec.Text())
	}
	// a git that reads and is new enough: no warning, no error
	gitSays(t, "git version 2.43.0\n", nil)
	if unread, err := checkGit(); unread || err != nil {
		t.Fatalf("a good git: unread %v, %v", unread, err)
	}
	// a git that cannot be run for another reason is an error too
	gitSays(t, "", os.ErrPermission)
	if _, err := checkGit(); err == nil {
		t.Fatal("a git that does not run passes")
	}
	// yars init goes on with a version that does not read
	gitSays(t, "git version zqweird7f3kq\n", nil)
	var out bytes.Buffer
	if err := cmdInitOut([]string{filepath.Join(t.TempDir(), "data")}, &out); err != nil {
		t.Fatalf("init with a version that does not read: %v", err)
	}
}
