package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"yars/internal/backup"
	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

// dataWithFinding is an initialised data folder with one engagement and one
// finding.
func dataWithFinding(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(r, config.Default(), openDB(t, dir))
	a := gitrepo.Author{Name: "t", Email: "t@t"}
	if err := st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFinding("acme", "SQL injection", a); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBackupWritesVerifiedZip(t *testing.T) {
	dir := dataWithFinding(t)
	out := filepath.Join(t.TempDir(), "b.zip")
	var log bytes.Buffer
	if err := cmdBackup([]string{"--data", dir, "--out", out}, &log); err != nil {
		t.Fatal(err)
	}
	rep, err := backup.Verify(out)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Engagements != 1 || rep.Findings != 1 || rep.HasKey {
		t.Fatalf("report %+v", rep)
	}
	if _, err := os.Stat(out + ".part"); !os.IsNotExist(err) {
		t.Fatal("the .part file is left behind")
	}
	if !strings.HasPrefix(log.String(), "wrote "+out+" (") || !strings.Contains(log.String(), "1 engagement, 1 finding)") {
		t.Fatalf("output %q", log.String())
	}
	l, _ := openDB(t, dir).AuditLog(1)
	if len(l) != 1 || l[0].Actor != "cli" || l[0].Action != "backup" || !strings.HasPrefix(l[0].Detail, "without key · ") {
		t.Fatalf("audit %+v", l)
	}
	// --key puts the secret key in
	withKey := filepath.Join(t.TempDir(), "k.zip")
	if err := cmdBackup([]string{"--data", dir, "--key", "--out", withKey}, &log); err != nil {
		t.Fatal(err)
	}
	if rep, err := backup.Verify(withKey); err != nil || !rep.HasKey {
		t.Fatalf("with key %+v %v", rep, err)
	}
}

func TestBackupRefusesExistingOut(t *testing.T) {
	dir := dataWithFinding(t)
	out := filepath.Join(t.TempDir(), "b.zip")
	if err := os.WriteFile(out, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := cmdBackup([]string{"--data", dir, "--out", out}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Fatalf("err %v", err)
	}
	if b, _ := os.ReadFile(out); string(b) != "mine" {
		t.Fatal("the file was overwritten")
	}
	if err := cmdBackup([]string{"--data", dir}, &bytes.Buffer{}); err == nil {
		t.Fatal("no --out accepted")
	}
}

func TestBackupRetriesInconsistent(t *testing.T) {
	dir := dataWithFinding(t)
	defer func(v func(string) (backup.Report, error)) { verifyBackup = v }(verifyBackup)

	runs := 0
	verifyBackup = func(p string) (backup.Report, error) {
		runs++
		if runs < 3 {
			return backup.Report{}, errors.New("engagements/acme: missing blob")
		}
		return backup.Verify(p)
	}
	out := filepath.Join(t.TempDir(), "b.zip")
	if err := cmdBackup([]string{"--data", dir, "--out", out}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if runs != 3 {
		t.Fatalf("verified %d times", runs)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}

	runs = 0
	verifyBackup = func(string) (backup.Report, error) {
		runs++
		return backup.Report{}, errors.New("engagements/acme: missing blob")
	}
	folder := t.TempDir()
	out = filepath.Join(folder, "c.zip")
	err := cmdBackup([]string{"--data", dir, "--out", out}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "could not take a consistent backup while the server is writing; try again") {
		t.Fatalf("err %v", err)
	}
	// the cause of the last try is kept: a fault that never goes away shows
	if !strings.Contains(err.Error(), "missing blob") {
		t.Fatalf("the last error is lost: %v", err)
	}
	if runs != backupTries {
		t.Fatalf("verified %d times, want %d", runs, backupTries)
	}
	if ents, _ := os.ReadDir(folder); len(ents) != 0 {
		t.Fatalf("files left: %v", ents)
	}
}

// A copy that fails (a file it cannot read) is tried again like one that
// does not verify, and the reason is shown.
func TestBackupRetriesWriteErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file")
	}
	dir := dataWithFinding(t)
	locked := filepath.Join(dir, ".yars", "unreadable.txt")
	if err := os.WriteFile(locked, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0o600)
	defer func(v func(string) (backup.Report, error)) { verifyBackup = v }(verifyBackup)
	verifyBackup = func(string) (backup.Report, error) {
		t.Fatal("verified a backup that failed to write")
		return backup.Report{}, nil
	}
	folder := t.TempDir()
	err := cmdBackup([]string{"--data", dir, "--out", filepath.Join(folder, "b.zip")}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "could not take a consistent backup") || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("err %v", err)
	}
	if ents, _ := os.ReadDir(folder); len(ents) != 0 {
		t.Fatalf("files left: %v", ents)
	}
}

// A backup written into the data folder would copy itself, and the next one
// both: it is refused.
func TestBackupRefusesOutInsideData(t *testing.T) {
	dir := dataWithFinding(t)
	for _, out := range []string{filepath.Join(dir, "b.zip"), filepath.Join(dir, "engagements", "acme", "b.zip")} {
		err := cmdBackup([]string{"--data", dir, "--out", out}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), "is inside the data folder") {
			t.Fatalf("%s: err %v", out, err)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%s was written", out)
		}
	}
}

// Where the target has no hard links (FAT, many network mounts) the backup
// is renamed into place.
func TestBackupWithoutHardLinks(t *testing.T) {
	dir := dataWithFinding(t)
	defer func(v func(string, string) error) { linkFile = v }(linkFile)
	linkFile = func(old, new string) error {
		return &os.LinkError{Op: "link", Old: old, New: new, Err: syscall.EPERM}
	}
	out := filepath.Join(t.TempDir(), "b.zip")
	if err := cmdBackup([]string{"--data", dir, "--out", out}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err := backup.Verify(out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(out + ".part"); !os.IsNotExist(err) {
		t.Fatal("the .part file is left behind")
	}
}

// Another backup writing the same file's .part is not disturbed, and a
// file that appears at --out meanwhile is not replaced.
func TestBackupLeavesOthersFiles(t *testing.T) {
	dir := dataWithFinding(t)
	out := filepath.Join(t.TempDir(), "b.zip")
	if err := os.WriteFile(out+".part", []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := cmdBackup([]string{"--data", dir, "--out", out}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), out+".part exists") {
		t.Fatalf("err %v", err)
	}
	if b, _ := os.ReadFile(out + ".part"); string(b) != "theirs" {
		t.Fatal("the other .part was changed")
	}
	os.Remove(out + ".part")

	defer func(v func(string) (backup.Report, error)) { verifyBackup = v }(verifyBackup)
	verifyBackup = func(p string) (backup.Report, error) {
		os.WriteFile(out, []byte("mine"), 0o600) // written while we verify
		return backup.Verify(p)
	}
	err = cmdBackup([]string{"--data", dir, "--out", out}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "exists already") {
		t.Fatalf("err %v", err)
	}
	if b, _ := os.ReadFile(out); string(b) != "mine" {
		t.Fatal("the file at --out was replaced")
	}
	if _, err := os.Stat(out + ".part"); !os.IsNotExist(err) {
		t.Fatal("the .part file is left behind")
	}
}

func TestRestoreCommandRoundTrip(t *testing.T) {
	dir := dataWithFinding(t)
	out := filepath.Join(t.TempDir(), "b.zip")
	if err := cmdBackup([]string{"--data", dir, "--out", out}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "restored")
	var log bytes.Buffer
	if err := cmdRestore([]string{"--from", out, "--data", dest}, &log); err != nil {
		t.Fatal(err)
	}
	if _, err := gitrepo.Open(dest); err != nil {
		t.Fatal(err)
	}
	openDB(t, dest)
	for _, want := range []string{"schema v", "1 engagement\n", "1 finding\n", "secret key: no\n",
		"stored AI and personal keys must be entered again\n", "next: yars serve --data " + dest + "\n"} {
		if !strings.Contains(log.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, log.String())
		}
	}
}

func TestRestoreNeedsBothFlags(t *testing.T) {
	t.Setenv(dataEnv, t.TempDir())
	for _, args := range [][]string{
		{"--from", "b.zip"},
		{"--data", filepath.Join(t.TempDir(), "new")},
		{},
	} {
		if err := cmdRestore(args, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "usage: yars restore --from") {
			t.Fatalf("%v: err %v", args, err)
		}
	}
}
