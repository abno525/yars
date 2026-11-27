//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/finding"
)

// busyAddr is an address a start cannot listen on: a start that gets as far
// as its listener ends there with an error, so a test never serves.
func busyAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// leftover writes a finding folder no commit holds into acme, as a server
// leaves it between a write and its commit.
func leftover(t *testing.T, dir string) string {
	t.Helper()
	left := filepath.Join(dir, "engagements", "acme", "findings", "F-009-in-flight", "finding.md")
	if err := os.MkdirAll(filepath.Dir(left), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(left, []byte("---\nid: F-009\ntitle: In flight\nauthor: alice\n---\n\n## Description\n\nx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return left
}

// While a server holds the data folder's lock, a second yars serve stops
// with one error before anything is read or written: the first server's
// uncommitted file stays, its tracked edit is not reset, its journal row is
// neither replayed nor removed, and nothing is repaired.
func TestServeRefusedWhileAnotherServes(t *testing.T) {
	r, _, _, _ := stoppedEdit(t)
	dir := r.Dir
	release, err := lockData(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	left := leftover(t, dir)
	// a tracked file the first server has checked out and not yet committed
	edited := "# in flight\n"
	if err := os.WriteFile(config.ConfigPath(dir), []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}

	err = cmdServe([]string{"--data", dir, "--addr", busyAddr(t)})
	if err == nil || err.Error() != "another yars serve runs on this data folder ("+dir+")" {
		t.Fatalf("a second start: %v", err)
	}
	if _, err := os.Stat(left); err != nil {
		t.Fatalf("the first server's file was removed: %v", err)
	}
	if b, _ := os.ReadFile(config.ConfigPath(dir)); string(b) != edited {
		t.Fatalf("the second start reset the work tree: %q", b)
	}
	d := openDB(t, dir)
	if rows, err := d.Intents(); err != nil || len(rows) != 1 {
		t.Fatalf("journal %+v %v", rows, err)
	}
	if l, _, _ := d.AuditQuery(db.AuditFilter{Action: "system.repair", Limit: 5}); len(l) != 0 {
		t.Fatalf("audit %+v", l)
	}
}

// A lock whose holder is gone is no lock: after the holder's file is closed
// (a server that was killed) the next start goes on, and the lock file is
// still there. When that start ends, its own lock is gone too.
func TestServeStartsAfterLockHolderGone(t *testing.T) {
	r, _, _, _ := stoppedEdit(t)
	dir := r.Dir
	release, err := lockData(dir)
	if err != nil {
		t.Fatal(err)
	}
	release()
	left := leftover(t, dir)

	err = cmdServe([]string{"--data", dir, "--addr", busyAddr(t)})
	if err == nil || strings.Contains(err.Error(), "another yars serve") || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("a start after the holder is gone: %v", err)
	}
	// the start got as far as its listener: the folder was made ready
	if _, err := os.Stat(left); !os.IsNotExist(err) {
		t.Fatal("the uncommitted folder is still there")
	}
	if rows, err := openDB(t, dir).Intents(); err != nil || len(rows) != 0 {
		t.Fatalf("journal %+v %v", rows, err)
	}
	if fi, err := os.Stat(dataLockPath(dir)); err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the lock file: %v %v", fi, err)
	}
	again, err := lockData(dir)
	if err != nil {
		t.Fatalf("the failed start kept the lock: %v", err)
	}
	again()
}

// The lock is on the file, not on the path: a start through a link to the
// data folder is refused while a server runs on the folder itself.
func TestServeLockThroughLink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("no links here: %v", err)
	}
	release, err := lockData(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	err = cmdServe([]string{"--data", link, "--addr", busyAddr(t)})
	if err == nil || !strings.HasPrefix(err.Error(), "another yars serve runs on this data folder (") {
		t.Fatalf("a start through a link: %v", err)
	}
}

// A folder without .yars is no data folder: no lock is taken there and no
// .yars is made for one.
func TestLockDataMakesNoFolder(t *testing.T) {
	dir := t.TempDir()
	release, err := lockData(dir)
	if err != nil {
		t.Fatal(err)
	}
	release()
	if _, err := os.Lstat(filepath.Join(dir, ".yars")); !os.IsNotExist(err) {
		t.Fatalf(".yars was made: %v", err)
	}
}

// The lock is for a second server only. The commands that write beside a
// running server keep working while it holds the lock, the lock file is no
// change in the main repository, and a backup leaves it out.
func TestCommandsBesideLockedServer(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	release, err := lockData(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var out bytes.Buffer
	for _, name := range []string{"ann", "bob"} {
		if err := cmdUseradd([]string{"--data", dir, "--role", "director", "--admin", name}, strings.NewReader("password-1\n"), &out); err != nil {
			t.Fatalf("useradd %s: %v", name, err)
		}
	}
	if err := cmdAdmin([]string{"--data", dir, "bob", "off"}, &out); err != nil {
		t.Fatalf("admin: %v", err)
	}
	if err := cmdDisabled(true, []string{"--data", dir, "bob"}, &out); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if code, err := cmdToken([]string{"add", "--data", dir, "ann"}, &out); err != nil || code != 0 {
		t.Fatalf("token add: %d %v", code, err)
	}
	zip := filepath.Join(t.TempDir(), "b.zip")
	if err := cmdBackup([]string{"--data", dir, "--out", zip}, &out); err != nil {
		t.Fatalf("backup: %v", err)
	}
	if err := cmdUserdel([]string{"--data", dir, "bob"}, &out); err != nil {
		t.Fatalf("userdel: %v", err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if err := cmdRestore([]string{"--from", zip, "--data", restored}, &out); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := os.Lstat(dataLockPath(restored)); !os.IsNotExist(err) {
		t.Fatalf("the backup holds the lock file: %v", err)
	}
	if b, err := exec.Command("git", "-C", dir, "status", "--porcelain").CombinedOutput(); err != nil || len(b) != 0 {
		t.Fatalf("git status with the lock file: %v\n%s", err, b)
	}
}

// The push hook is a child of the server that holds the lock: a push goes
// through while the lock is held.
func TestPushWhileServerHoldsLock(t *testing.T) {
	p := newPushEnv(t)
	release, err := lockData(filepath.Dir(filepath.Dir(p.repo.Dir)))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	p.editFinding(func(f *finding.Finding) { f.SetSection("Impact", "Full database read.") })
	if out, err := p.git("push", "-q", "origin", "HEAD"); err != nil {
		t.Fatalf("a push beside the lock: %v\n%s", err, out)
	}
}
