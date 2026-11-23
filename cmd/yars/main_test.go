package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/secret"
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
	// the secret key exists, is private and is never tracked
	info, err = os.Stat(secret.KeyPath(dir))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("secret key %v %v", info, err)
	}
	if out, _ := exec.Command("git", "-C", dir, "check-ignore", ".yars/secret.key").Output(); len(out) == 0 {
		t.Fatal("secret key not ignored")
	}
}

// The admin flag is set at useradd or with yars admin; user changes are
// audited.
func TestAdminCommand(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdUseradd([]string{"--data", dir, "--role", "pentester", "--admin", "ann"}, strings.NewReader("password-1\n"), &out); err != nil {
		t.Fatal(err)
	}
	d := openDB(t, dir)
	if u, _, _ := d.User("ann"); !u.IsAdmin || u.Role != "pentester" {
		t.Fatalf("ann %+v", u)
	}
	if err := cmdAdmin([]string{"--data", dir, "ann", "off"}, &out); err != nil {
		t.Fatal(err)
	}
	if u, _, _ := d.User("ann"); u.IsAdmin {
		t.Fatal("admin flag still on")
	}
	if err := cmdAdmin([]string{"--data", dir, "ann", "maybe"}, &out); err == nil {
		t.Fatal("bad value accepted")
	}
	l, _ := d.AuditLog(10)
	if len(l) != 2 || l[0].Action != "user.admin" || l[1].Action != "user.add" || l[1].Detail != "role pentester, admin" {
		t.Fatalf("audit %+v", l)
	}
}

// yars token add makes scoped tokens; revoke --id drops one.
func TestTokenCommandScopes(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	d := openDB(t, dir)
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	var out bytes.Buffer
	if code, err := cmdToken([]string{"add", "--data", dir, "--kind", "git", "--scopes", "read", "--engagements", "acme", "--days", "30", "bob"}, &out); code != 0 {
		t.Fatal(code, err)
	}
	if code, _ := cmdToken([]string{"add", "--data", dir, "--scopes", "fly", "bob"}, &out); code == 0 {
		t.Fatal("bad scope accepted")
	}
	ts, _ := d.UserTokens("bob")
	if len(ts) != 1 || ts[0].Kind != "git" || !ts[0].ReadOnly() || ts[0].Expires == "" || ts[0].Engagements[0] != "acme" {
		t.Fatalf("tokens %+v", ts)
	}
	// list names each token by the id revoke --id takes (backlog, M9)
	var list bytes.Buffer
	if code, err := cmdToken([]string{"list", "--data", dir}, &list); code != 0 {
		t.Fatal(code, err)
	}
	if !strings.HasPrefix(list.String(), strconv.FormatInt(ts[0].ID, 10)+"\tbob\tgit\t") {
		t.Fatalf("list does not start with the token's id:\n%s", list.String())
	}
	// revoke --id takes that token only (review: with one token, revoking
	// every one would pass)
	if code, err := cmdToken([]string{"add", "--data", dir, "--kind", "mcp", "bob"}, &out); code != 0 {
		t.Fatal(code, err)
	}
	if code, err := cmdToken([]string{"revoke", "--data", dir, "--id", strconv.FormatInt(ts[0].ID, 10), "bob"}, &out); code != 0 {
		t.Fatal(code, err)
	}
	if left, _ := d.UserTokens("bob"); len(left) != 1 || left[0].ID == ts[0].ID || left[0].Kind != "mcp" {
		t.Fatalf("after revoke --id %+v", left)
	}
}

// Revoking the tokens of an account that does not exist is an error (a
// typo would otherwise look like success), and writes no audit entry
// (backlog, M9).
func TestTokenRevokeUnknownUser(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, args := range [][]string{{"revoke", "--data", dir, "bobb"}, {"revoke", "--data", dir, "--id", "7", "bobb"}} {
		if code, err := cmdToken(args, &out); code != 1 || err == nil || err.Error() != "unknown user bobb" {
			t.Errorf("%v: code %d err %v", args, code, err)
		}
	}
	if log, _ := openDB(t, dir).AuditLog(10); len(log) != 0 {
		t.Fatalf("audit %+v", log)
	}
	// a database that does not answer is said as such, not as an unknown
	// account (D9; review)
	if _, err := openDB(t, dir).Exec("ALTER TABLE users RENAME TO users_away"); err != nil {
		t.Fatal(err)
	}
	if code, err := cmdToken([]string{"revoke", "--data", dir, "bob"}, &out); code != 1 || err == nil || strings.Contains(err.Error(), "unknown user") {
		t.Fatalf("code %d err %v", code, err)
	}
}

// A .gitignore written by an older YARS has an older comment over the same
// lines: it is replaced by the current one, not joined by it; the other
// lines stay, and a second run changes nothing (backlog, M9).
func TestIgnoreReplacesOldComment(t *testing.T) {
	for _, old := range []string{"# password hashes stay on the server", "# password hashes and API tokens stay on the server"} {
		dir := t.TempDir()
		gi := filepath.Join(dir, ".gitignore")
		os.WriteFile(gi, []byte("node_modules/\n"+old+"\n.yars/users.yaml\n"), 0o644)
		if changed, err := writeIgnore(dir); !changed || err != nil {
			t.Fatalf("%s: %v %v", old, changed, err)
		}
		b, _ := os.ReadFile(gi)
		got := string(b)
		if strings.Contains(got, old) || strings.Count(got, "# ") != 1 || !strings.HasPrefix(got, "node_modules/\n# accounts, tokens, chat and workflow state stay on the server\n.yars/users.yaml\n") {
			t.Fatalf("%s:\n%s", old, got)
		}
		if changed, _ := writeIgnore(dir); changed {
			t.Fatalf("%s: a second run changed it", old)
		}
	}
}

// A script rule that cannot run is reported for each finding it was to
// check, and an error-level one fails the run: only the rules' own load
// problems are printed once (M34 review of 0ae5430).
func TestLintShowsScriptFailure(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	rdir := filepath.Join(dir, ".yars", "rules")
	os.MkdirAll(rdir, 0o755) // init writes no rules, so no folder
	os.WriteFile(filepath.Join(rdir, "boom.yaml"), []byte("- id: boom\n  level: error\n  script: boom.sh\n"), 0o644)
	os.WriteFile(filepath.Join(rdir, "boom.sh"), []byte("#!/bin/sh\necho kaputt >&2\nexit 3\n"), 0o755)
	r, _ := gitrepo.Open(dir)
	st := store.New(r, config.Default(), nil)
	a := gitrepo.Author{Name: "t", Email: "t@t"}
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a)
	st.CreateFinding("acme", "Good title", a)
	var out bytes.Buffer
	code, err := cmdLint([]string{"--data", dir, "--all"}, &out)
	if code != 1 || err != nil || !strings.Contains(out.String(), "acme/F-001 error boom: rule failed") {
		t.Fatalf("code %d err %v:\n%s", code, err, out.String())
	}
}

// A scope is one engagement or finding: an engagement with no findings yet
// is checked (0 findings), a second scope or a scope with --staged is
// refused for what it is (M34 review of 1748f2e and d9a5d10).
func TestLintScopeMessages(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	r, _ := gitrepo.Open(dir)
	store.New(r, config.Default(), nil).CreateEngagement(store.Engagement{ID: "new", Name: "New"}, gitrepo.Author{Name: "t", Email: "t@t"})
	var out bytes.Buffer
	if code, err := cmdLint([]string{"--data", dir, "new"}, &out); code != 0 || err != nil || !strings.Contains(out.String(), "0 finding(s) checked") {
		t.Errorf("an empty engagement: code %d err %v", code, err)
	}
	for args, want := range map[string][]string{
		"one scope only":            {"--data", dir, "new", "F-001"},
		"it takes no scope":         {"--staged", "new"},
		"flags go before the scope": {"--data", dir, "new", "--all"},
	} {
		if code, err := cmdLint(want, &out); code != 2 || err == nil || !strings.Contains(err.Error(), args) {
			t.Errorf("%v: code %d err %v", want, code, err)
		}
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
	if err := cmdUseradd([]string{"--data", dir, "--role", "reviewer", "bob"}, strings.NewReader("password-1\n"), &out); err != nil {
		t.Fatal(err)
	}
	if err := cmdUseradd([]string{"--data", dir, "--role", "reviewer", "bob"}, strings.NewReader("password-1\n"), &out); err == nil {
		t.Fatal("duplicate user")
	}
	if err := cmdUseradd([]string{"--data", dir, "--role", "admin", "eve"}, strings.NewReader("password-1\n"), &out); err == nil {
		t.Fatal("unknown role accepted")
	}
	d := openDB(t, dir)
	u, ok, _ := d.User("bob")
	if !ok || u.Role != "reviewer" || u.PasswordHash == "" || u.PasswordHash == "password-1" {
		t.Fatalf("bob %+v", u)
	}
	if err := cmdPasswd([]string{"--data", dir, "bob"}, strings.NewReader("password-2\n"), &out); err != nil {
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

// useradd and passwd ask for the website's shortest password, 10 characters
// (characters, not bytes): a shorter one is refused and changes nothing.
func TestCLIPasswordLength(t *testing.T) {
	dir := t.TempDir()
	if err := cmdInit([]string{dir}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	const short = "password too short: at least 10 characters"
	if err := cmdUseradd([]string{"--data", dir, "bob"}, strings.NewReader("change-me\n"), &out); err == nil || err.Error() != short {
		t.Fatalf("useradd with 9 characters: %v", err)
	}
	d := openDB(t, dir)
	if _, ok, _ := d.User("bob"); ok {
		t.Fatal("bob added with a short password")
	}
	if err := cmdUseradd([]string{"--data", dir, "bob"}, strings.NewReader("change-me!\n"), &out); err != nil {
		t.Fatalf("useradd with 10 characters: %v", err)
	}
	u, _, _ := d.User("bob")
	for _, pw := range []string{"123456789", "äääääääää"} {
		if err := cmdPasswd([]string{"--data", dir, "bob"}, strings.NewReader(pw+"\n"), &out); err == nil || err.Error() != short {
			t.Fatalf("passwd %q: %v", pw, err)
		}
	}
	if u2, _, _ := d.User("bob"); u2.PasswordHash != u.PasswordHash {
		t.Fatal("password changed to a short one")
	}
	if err := cmdPasswd([]string{"--data", dir, "bob"}, strings.NewReader("1234567890\n"), &out); err != nil {
		t.Fatalf("passwd with 10 characters: %v", err)
	}
	if u3, _, _ := d.User("bob"); u3.PasswordHash == u.PasswordHash {
		t.Fatal("password unchanged")
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
	d := openDB(t, dir)
	st := store.New(r, config.Default(), d)
	a := gitrepo.Author{Name: "t", Email: "t@t"}
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a)
	st.CreateFinding("acme", "SQL injection", a)
	// only finished findings are exported (R10)
	if err := d.TxFor("acme", func(tx *db.Tx) error { return tx.PutState("acme", "F-001", db.State{Status: "complete"}) }); err != nil {
		t.Fatal(err)
	}
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
	if err := d.TxFor("acme", func(tx *db.Tx) error { return tx.PutState("acme", "F-001", db.State{Status: workflow.Withdrawn}) }); err != nil {
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
	withTestRules(t, dir)
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
	// a broken rules file is reported once, before the findings, and also
	// when no finding is checked (backlog, M5)
	if err := os.WriteFile(filepath.Join(dir, ".yars", "rules", "broken.yaml"), []byte("rules: [\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code, err := cmdLint([]string{"--data", dir}, &out); code != 1 || err != nil || strings.Count(out.String(), "rules/broken.yaml") != 1 || !strings.HasPrefix(out.String(), "rules error rules/broken.yaml: ") {
		t.Errorf("a broken rules file: code %d err %v:\n%s", code, err, out.String())
	}
	empty := t.TempDir()
	if err := cmdInit([]string{empty}); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(empty, ".yars", "rules"), 0o755) // init writes no rules, so no folder
	os.WriteFile(filepath.Join(empty, ".yars", "rules", "broken.yaml"), []byte("rules: [\n"), 0o644)
	out.Reset()
	if code, err := cmdLint([]string{"--data", empty}, &out); code != 1 || err != nil || !strings.Contains(out.String(), "rules/broken.yaml") {
		t.Errorf("no findings: code %d err %v:\n%s", code, err, out.String())
	}
	os.Remove(filepath.Join(dir, ".yars", "rules", "broken.yaml"))
	// the finding in a scope is named as the website names it: its folder,
	// its ID or its number (backlog, M5)
	for _, scope := range []string{"acme/F-001", "acme/1", "acme/F-001-bad-title"} {
		out.Reset()
		if code, err := cmdLint([]string{"--data", dir, scope}, &out); code != 1 || err != nil || !strings.Contains(out.String(), "acme/F-001 error") || !strings.Contains(out.String(), "1 finding(s) checked") {
			t.Errorf("%s: code %d err %v:\n%s", scope, code, err, out.String())
		}
	}
	// flags go before the scope: anything after it is refused, never
	// ignored (backlog, M5)
	out.Reset()
	if code, err := cmdLint([]string{"--data", dir, "acme", "--all"}, &out); code != 2 || err == nil || !strings.Contains(err.Error(), `flags go before the scope; "--all" is after it`) {
		t.Errorf("a flag after the scope: code %d err %v", code, err)
	}
	// a scope that matches nothing is an error, not "0 checked" (backlog, M5)
	for _, scope := range []string{"acme/F-009-gone", "nope", "nope/F-001-bad-title"} {
		out.Reset()
		if code, err := cmdLint([]string{"--data", dir, scope}, &out); code != 2 || err == nil || !strings.Contains(err.Error(), "no finding matches "+scope) {
			t.Errorf("%s: code %d err %v", scope, code, err)
		}
	}
}
