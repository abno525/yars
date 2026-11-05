package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/store"
	"yars/internal/workflow"
)

// The hook maps GIT_DIR to its engagement even when the data path goes
// through a symlink (git hands the hook the physical path).
func TestEngOfGitDirSymlink(t *testing.T) {
	real := t.TempDir()
	os.MkdirAll(filepath.Join(real, "engagements", "acme", ".git"), 0o755)
	link := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(real, link); err != nil {
		t.Skip("no symlinks here")
	}
	if got := engOfGitDir(link, filepath.Join(real, "engagements", "acme", ".git")); got != "acme" {
		t.Fatalf("got %q", got)
	}
	if got := engOfGitDir(link, filepath.Join(real, ".git")); got != "" {
		t.Fatalf("main repo mapped to %q", got)
	}
}

// init creates the database next to the config: private and never in git.
func TestInitCreatesDatabase(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(db.Path(dir))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("database %v %v", info, err)
	}
	if out, _ := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); len(out) != 0 {
		t.Fatalf("database not ignored: %s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, ".yars", "users.yaml")); err == nil {
		t.Fatal("init still writes users.yaml")
	}
}

func openDB(t *testing.T, dir string) *db.DB {
	t.Helper()
	d, err := db.Open(db.Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

// Accounts live in the database and are managed with useradd, passwd, role
// and userdel.
func TestUserCommands(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdUseradd([]string{"--data", dir, "--role", "reviewer", "bob"}, strings.NewReader("pw1\n"), &out); err != nil {
		t.Fatal(err)
	}
	if err := cmdUseradd([]string{"--data", dir, "--role", "reviewer", "bob"}, strings.NewReader("pw1\n"), &out); err == nil {
		t.Fatal("duplicate user")
	}
	if err := cmdUseradd([]string{"--data", dir, "--role", "admin", "eve"}, strings.NewReader("pw\n"), &out); err == nil {
		t.Fatal("unknown role accepted")
	}
	d := openDB(t, dir)
	u, ok, _ := d.User("bob")
	if !ok || u.Role != "reviewer" || u.PasswordHash == "" || u.PasswordHash == "pw1" {
		t.Fatalf("bob %+v", u)
	}
	if err := cmdPasswd([]string{"--data", dir, "bob"}, strings.NewReader("pw2\n"), &out); err != nil {
		t.Fatal(err)
	}
	if u2, _, _ := d.User("bob"); u2.PasswordHash == u.PasswordHash {
		t.Fatal("password unchanged")
	}
	if err := cmdRole([]string{"--data", dir, "bob", "director"}, &out); err != nil {
		t.Fatal(err)
	}
	if u3, _, _ := d.User("bob"); u3.Role != "director" {
		t.Fatalf("role %q", u3.Role)
	}
	if err := cmdUserdel([]string{"--data", dir, "bob"}, &out); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := d.User("bob"); ok {
		t.Fatal("bob not deleted")
	}
	if err := cmdUserdel([]string{"--data", dir, "bob"}, &out); err == nil {
		t.Fatal("deleting a missing user succeeded")
	}
}

func TestExportCLI(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"docx.yaml", "confluence.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, ".yars", "exporters", f)); err != nil {
			t.Fatalf("default exporter %s missing", f)
		}
	}
	r, _ := gitrepo.Open(dir)
	st := store.New(r, config.Default(), openDB(t, dir))
	a := gitrepo.Author{Name: "t", Email: "t@t"}
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a)
	st.CreateFinding("acme", "SQL injection", a)
	out := filepath.Join(t.TempDir(), "r.html")
	var log bytes.Buffer
	if code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--out", out, "acme", "F-001-sql-injection"}, &log); err != nil || code != 0 {
		t.Fatalf("code %d err %v: %s", code, err, log.String())
	}
	if b, _ := os.ReadFile(out); !strings.Contains(string(b), "SQL injection") {
		t.Fatalf("output %q", b)
	}
	if code, _ := cmdExport([]string{"--data", dir, "--exporter", "nope", "acme"}, &log); code == 0 {
		t.Fatal("unknown exporter accepted")
	}
	// a withdrawn finding is never exported, even when named
	if err := st.Transition("acme", "F-001-sql-injection", workflow.Withdraw, "duplicate", config.User{Username: "t", Role: "pentester"}); err != nil {
		t.Fatal(err)
	}
	if code, err := cmdExport([]string{"--data", dir, "--exporter", "confluence", "--out", out, "acme", "F-001-sql-injection"}, &log); code == 0 || err == nil {
		t.Fatal("withdrawn finding exported")
	}
}

func TestLintCommand(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, ".yars", "rules", "style.yaml")); err != nil || !strings.Contains(string(b), "title-no-trailing-dot") {
		t.Fatalf("example rules not written: %v", err)
	}
	r, _ := gitrepo.Open(dir)
	st := store.New(r, config.Default(), nil)
	a := gitrepo.Author{Name: "t", Email: "t@t"}
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a)
	st.CreateFinding("acme", "Bad title.", a)
	st.CreateFinding("acme", "Good title", a)

	var out bytes.Buffer
	code, err := cmdLint([]string{"--data", dir, "--fast"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 || !strings.Contains(out.String(), "acme/F-001 error title-no-trailing-dot") || strings.Contains(out.String(), "F-002 error title") {
		t.Fatalf("code %d output:\n%s", code, out.String())
	}
	out.Reset()
	code, _ = cmdLint([]string{"--data", dir, "--fast", "acme/F-002-good-title"}, &out)
	if code != 0 || strings.Contains(out.String(), "F-001") {
		t.Fatalf("scoped lint code %d:\n%s", code, out.String())
	}
}
