//go:build unix

package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/store"
)

// wideEntries lists the entries under dir that the group or others can
// reach; with skipGit it leaves out what git itself wrote (.git folders).
func wideEntries(t *testing.T, dir string, skipGit bool) []string {
	t.Helper()
	var wide []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if skipGit && d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink == 0 && info.Mode().Perm()&0o077 != 0 {
			rel, _ := filepath.Rel(dir, p)
			wide = append(wide, rel+" "+info.Mode().Perm().String())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return wide
}

// fillData sets up a data folder as a server does: init, an engagement, a
// finding, a rule script, the git endpoint's hooks.
func fillData(t *testing.T, dir string) {
	t.Helper()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := openDB(t, dir)
	st := store.New(r, config.Default(), d)
	a := gitrepo.Author{Name: "t", Email: "t@t"}
	if err := st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFinding("acme", "SQL injection", a); err != nil {
		t.Fatal(err)
	}
	if err := st.EditSettings("rule", a, func(func(string) ([]byte, error)) ([]store.SettingsFile, error) {
		return []store.SettingsFile{{Path: ".yars/rules/x.sh", Data: []byte("#!/bin/sh\n"), Exec: true}}, nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	au := auth.New(d)
	gs := gitServer(r, au, auth.NewTokens(d), st, "/usr/bin/yars", func(string) {})
	if err := gs.Setup(); err != nil {
		t.Fatal(err)
	}
}

// What YARS itself writes into a data folder is the service user's alone,
// whatever the umask: folders 0700, files 0600, scripts 0700 (pre1 2.23).
func TestDataFilesPrivate(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	dir := filepath.Join(t.TempDir(), "data")
	fillData(t, dir)
	if wide := wideEntries(t, dir, true); len(wide) > 0 {
		t.Fatalf("open to the group or others:\n%s", strings.Join(wide, "\n"))
	}
	if info, err := os.Stat(filepath.Join(dir, ".yars", "rules", "x.sh")); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("rule script %v %v", info, err)
	}
	// a restore writes every file itself: private too, .git included,
	// though the backed-up .git was not
	zip := filepath.Join(t.TempDir(), "b.zip")
	if err := cmdBackup([]string{"--data", dir, "--out", zip}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	back := filepath.Join(t.TempDir(), "back")
	if err := cmdRestore([]string{"--from", zip, "--data", back}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if wide := wideEntries(t, back, false); len(wide) > 0 {
		t.Fatalf("restored, open to the group or others (%d), first:\n%s", len(wide), strings.Join(wide[:min(len(wide), 10)], "\n"))
	}
	if info, err := os.Stat(filepath.Join(back, ".yars", "rules", "x.sh")); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("restored rule script %v %v", info, err)
	}
}

// The server-side commands run with a private umask, so what git writes
// (.git, hooks, objects) is the service user's alone too (pre1 2.23).
func TestServerCommandsPrivateUmask(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	t.Cleanup(privateUmask())
	dir := filepath.Join(t.TempDir(), "data")
	fillData(t, dir)
	if wide := wideEntries(t, dir, false); len(wide) > 0 {
		t.Fatalf("open to the group or others (%d), first:\n%s", len(wide), strings.Join(wide[:min(len(wide), 10)], "\n"))
	}
	// a clone's own commands keep the user's umask
	for cmd, want := range map[string]bool{
		"serve": true, "init": true, "useradd": true, "passwd": true, "role": true, "admin": true, "userdel": true,
		"unlock": true, "token": true, "migrate": true, "backup": true, "restore": true, "seed": true, "export": true,
		"hook pre-receive": true, "hook install": false, "mcp": false, "lint": false, "use": false, "version": false,
	} {
		if got := serverSide(strings.Fields(cmd)); got != want {
			t.Errorf("serverSide(%s) = %v", cmd, got)
		}
	}
}

// yars export does not replace a file without --force, and writes its file
// for the user alone (pre1 2.23).
func TestExportCLIRefusesOverwrite(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	dir := exportFixture(t)
	out := filepath.Join(t.TempDir(), "r.html")
	if err := os.WriteFile(out, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--out", out, "acme", "F-001"}, &log)
	if code != 2 || err == nil || err.Error() != out+" exists already (use --force to replace it)" {
		t.Fatalf("code %d err %v", code, err)
	}
	if b, _ := os.ReadFile(out); string(b) != "mine" {
		t.Fatal("the file was overwritten")
	}
	if l, _ := openDB(t, dir).AuditLog(5); len(l) != 0 {
		t.Fatalf("a refused export is in the audit log: %+v", l)
	}
	// --force replaces it, and the new file is private though the old was not
	if code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--force", "--out", out, "acme", "F-001"}, &log); code != 0 || err != nil {
		t.Fatalf("--force: code %d err %v", code, err)
	}
	b, _ := os.ReadFile(out)
	info, _ := os.Stat(out)
	if !strings.Contains(string(b), "SQL injection") || info.Mode().Perm() != 0o600 {
		t.Fatalf("after --force: mode %v, %d bytes", info.Mode().Perm(), len(b))
	}
	// a link is replaced, not followed
	target := filepath.Join(t.TempDir(), "target")
	os.WriteFile(target, []byte("mine"), 0o644)
	link := filepath.Join(t.TempDir(), "l.html")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("no symlinks here")
	}
	if code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--out", link, "acme", "F-001"}, &log); code != 2 || err == nil {
		t.Fatalf("a link: code %d err %v", code, err)
	}
	if code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--force", "--out", link, "acme", "F-001"}, &log); code != 0 || err != nil {
		t.Fatalf("a link with --force: code %d err %v", code, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "mine" {
		t.Fatal("the link's target was written")
	}
	// a new file is private
	fresh := filepath.Join(t.TempDir(), "n.html")
	if code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--out", fresh, "acme", "F-001"}, &log); code != 0 || err != nil {
		t.Fatalf("a new file: code %d err %v", code, err)
	}
	if info, err := os.Stat(fresh); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("a new file: %v %v", info, err)
	}
}
