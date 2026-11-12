package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

// legacyRepo builds a data repo in the layout used before the database:
// accounts in YAML, workflow state in the front matter, chat in chat.jsonl.
func legacyRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	r, err := gitrepo.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	hash := testHash(t, "pw")
	files := map[string]string{
		".yars/config.yaml":                "severities: [critical, high, medium, low, info]\n",
		".gitignore":                       ".yars/users.yaml\n.yars/tokens.yaml\n",
		".gitattributes":                   "*.png binary\nchat.jsonl merge=union\n",
		"engagements/acme/engagement.yaml": "name: ACME\ntype: pentest\n",
		"engagements/acme/findings/F-001-sqli/finding.md": "---\nid: F-001\ntitle: SQLi\nstatus: verification\nseverity: high\nauthor: alice\nreviewers:\n    - bob\n    - carol\ncleared_by:\n    - bob\n---\n\n## Impact\n\nDB read.\n",
		"engagements/acme/findings/F-001-sqli/chat.jsonl": `{"id":"aaaaaaaaaaaa","ts":"2026-11-04T10:00:00Z","user":"bob","text":"PoC?","section":"Impact"}` + "\n" +
			`{"id":"bbbbbbbbbbbb","ts":"2026-11-04T10:05:00Z","user":"alice","event":"submit"}` + "\n",
		"engagements/acme/findings/F-002-xss/finding.md": "---\nid: F-002\ntitle: XSS\nstatus: draft\nauthor: alice\nreviewers: []\nreturned: {by: bob, reason: add steps}\n---\n\n## Impact\n\nx\n",
		"engagements/rt/engagement.yaml":                 "name: RT\ntype: retest\nsource: acme\n",
		"engagements/rt/findings/F-001-sqli/finding.md":  "---\nid: F-001\ntitle: SQLi\nstatus: reported\nauthor: alice\nretest: {source: acme/F-001-sqli, result: not_fixed}\n---\n\n## Impact\n\nx\n",
	}
	var paths []string
	for p, body := range files {
		os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755)
		os.WriteFile(filepath.Join(dir, p), []byte(body), 0o644)
		paths = append(paths, p)
	}
	if err := r.Commit(paths, "old layout", system); err != nil {
		t.Fatal(err)
	}
	users := []config.User{{Username: "alice", Role: "pentester", PasswordHash: hash}, {Username: "bob", Role: "reviewer", PasswordHash: hash}}
	if err := config.SaveUsers(dir, users); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, ".yars", "tokens.yaml"), []byte("- user: bob\n  sha256: "+strings.Repeat("ab", 32)+"\n  created: \"2026-11-01T00:00:00Z\"\n"), 0o600)
	return dir
}

func TestMigrate(t *testing.T) {
	dir := legacyRepo(t)
	if items := legacyItems(dir); len(items) == 0 {
		t.Fatal("legacy layout not detected")
	}
	var out bytes.Buffer
	if err := cmdMigrate([]string{"--data", dir}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if items := legacyItems(dir); len(items) != 0 {
		t.Fatalf("still legacy: %v", items)
	}
	d := openDB(t, dir)
	// accounts and tokens
	if us, _ := d.Users(); len(us) != 2 {
		t.Fatalf("users %+v", us)
	}
	if u, ok, _ := d.TokenUser(strings.Repeat("ab", 32)); !ok || u != "bob" {
		t.Fatal("token not migrated")
	}
	for _, f := range []string{"users.yaml", "tokens.yaml"} {
		if _, err := os.Stat(filepath.Join(dir, ".yars", f)); err == nil {
			t.Fatalf("%s left on disk", f)
		}
	}
	// state is in the database, the files are content only, and bob's
	// clearance still counts (it was given for this content)
	r, _ := gitrepo.Open(dir)
	st := store.New(r, config.Default(), d)
	ref, err := st.Finding("acme", "F-001-sqli")
	if err != nil {
		t.Fatal(err)
	}
	m := ref.F.Meta
	if m.Status != "verification" || !reflect.DeepEqual(m.Reviewers, []string{"bob", "carol"}) || !reflect.DeepEqual(m.ClearedBy, []string{"bob"}) {
		t.Fatalf("state %+v", m)
	}
	if b := string(ref.F.Bytes()); strings.Contains(b, "status") || strings.Contains(b, "reviewers") || !strings.Contains(b, "DB read.") {
		t.Fatalf("file:\n%s", b)
	}
	if ref, _ := st.Finding("acme", "F-002-xss"); ref.F.Meta.Returned == nil || ref.F.Meta.Returned.Reason != "add steps" {
		t.Fatalf("returned %+v", ref.F.Meta.Returned)
	}
	if ref, _ := st.Finding("rt", "F-001-sqli"); ref.F.Meta.Retest == nil || ref.F.Meta.Retest.Result != "not_fixed" || ref.F.Meta.Retest.Source != "acme/F-001-sqli" {
		t.Fatalf("retest %+v", ref.F.Meta.Retest)
	}
	// already reported findings stay reported, approved for their content
	if ref, _ := st.Finding("rt", "F-001-sqli"); ref.F.Meta.Status != "reported" {
		t.Fatalf("status %q", ref.F.Meta.Status)
	}
	if s, _ := d.State("rt", "F-001"); s.ApprovedHash == "" {
		t.Fatal("approval not bound to the migrated content")
	}
	// chat moved into the database, files removed from git
	msgs, _ := st.Chat("acme", "F-001-sqli")
	if len(msgs) != 2 || msgs[0].Text != "PoC?" || msgs[1].Event != "submit" {
		t.Fatalf("chat %+v", msgs)
	}
	if r.Tracked("engagements/acme/findings/F-001-sqli/chat.jsonl") {
		t.Fatal("chat.jsonl still tracked")
	}
	if ga, _ := os.ReadFile(filepath.Join(dir, ".gitattributes")); strings.Contains(string(ga), "chat.jsonl") || !strings.Contains(string(ga), "*.png binary") {
		t.Fatalf(".gitattributes %q", ga)
	}
	if st, _ := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); len(st) != 0 {
		t.Fatalf("uncommitted after migrate: %s", st)
	}
	// every engagement became its own repository, keeping its history, and
	// the main repo points at it
	for _, e := range []string{"acme", "rt"} {
		er, err := st.EngRepo(e)
		if err != nil {
			t.Fatalf("%s is not a repository: %v", e, err)
		}
		log, _ := exec.Command("git", "-C", er.Dir, "log", "--format=%s").Output()
		if !strings.Contains(string(log), "old layout") || strings.Contains(string(log), "init") {
			t.Fatalf("%s history:\n%s", e, log)
		}
		if b, _ := os.ReadFile(filepath.Join(er.Dir, "engagement.yaml")); len(b) == 0 {
			t.Fatalf("%s lost engagement.yaml", e)
		}
		head, _ := er.Head()
		if link, _ := r.Gitlink("HEAD", "engagements/"+e); link != head {
			t.Fatalf("%s pointer %q, head %q", e, link, head)
		}
		if st, _ := exec.Command("git", "-C", er.Dir, "status", "--porcelain").Output(); len(st) != 0 {
			t.Fatalf("%s dirty after split: %s", e, st)
		}
	}
	if gm, _ := os.ReadFile(filepath.Join(dir, ".gitmodules")); !strings.Contains(string(gm), "url = ../e/acme") {
		t.Fatalf(".gitmodules:\n%s", gm)
	}
	if files, _ := exec.Command("git", "-C", dir, "ls-files", "engagements/acme/findings").Output(); len(files) != 0 {
		t.Fatalf("main repo still tracks finding files:\n%s", files)
	}
	// a second run changes nothing
	head, _ := r.Head()
	out.Reset()
	if err := cmdMigrate([]string{"--data", dir}, &out); err != nil {
		t.Fatal(err)
	}
	if h, _ := r.Head(); h != head {
		t.Fatal("second migrate made a commit")
	}
	if msgs, _ := st.Chat("acme", "F-001-sqli"); len(msgs) != 2 {
		t.Fatalf("chat duplicated: %d", len(msgs))
	}
}

// If the migration commit fails, the working tree is left exactly as it was
// (a dirty tree would make every push fail), and a re-run finishes the job
// without duplicating chat.
// A file the main repository ignored stays out of the engagement's own
// repository when the migration makes it (its import commit took every
// file) (backlog, M11).
func TestMigrateKeepsIgnoredFilesOut(t *testing.T) {
	dir := legacyRepo(t)
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".yars/users.yaml\n.yars/tokens.yaml\n*.tmp\n"), 0o644)
	gitT(t, dir, "commit", "-qam", "ignore scratch files")
	os.WriteFile(filepath.Join(dir, "engagements", "acme", "findings", "F-001-sqli", "scratch.tmp"), []byte("local notes"), 0o644)
	os.WriteFile(filepath.Join(dir, "engagements", "acme", "loose.md"), []byte("not ignored"), 0o644)
	var out bytes.Buffer
	if err := cmdMigrate([]string{"--data", dir}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	tracked, err := gitIn(filepath.Join(dir, "engagements", "acme"), "ls-files")
	if err != nil || strings.Contains(tracked, "scratch.tmp") || !strings.Contains(tracked, "loose.md") {
		t.Fatalf("tracked:\n%s", tracked)
	}
}

// A finding folder copied by hand with its chat.jsonl holds messages whose
// ids another finding's chat already has: ids are unique, so they are not
// copied, and the migration says so instead of dropping them silently
// (backlog, M10).
func TestMigrateReportsChatOfCopies(t *testing.T) {
	dir := legacyRepo(t)
	src := filepath.Join(dir, "engagements", "acme", "findings", "F-001-sqli")
	dst := filepath.Join(dir, "engagements", "acme", "findings", "F-003-sqli-copy")
	os.MkdirAll(dst, 0o755)
	b, _ := os.ReadFile(filepath.Join(src, "finding.md"))
	os.WriteFile(filepath.Join(dst, "finding.md"), []byte(strings.Replace(string(b), "id: F-001", "id: F-003", 1)), 0o644)
	c, _ := os.ReadFile(filepath.Join(src, "chat.jsonl"))
	os.WriteFile(filepath.Join(dst, "chat.jsonl"), c, 0o644)
	var out bytes.Buffer
	if err := cmdMigrate([]string{"--data", dir}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "2 chat messages of acme/F-003 are already acme/F-001's: not copied") {
		t.Fatalf("output:\n%s", out.String())
	}
}

// An API token whose account is gone from users.yaml is skipped with a
// line saying so; the migration goes on and finishes (backlog, M10).
func TestMigrateSkipsTokenOfMissingUser(t *testing.T) {
	dir := legacyRepo(t)
	toks := "- user: bob\n  sha256: " + strings.Repeat("ab", 32) + "\n- user: zed\n  sha256: " + strings.Repeat("cd", 32) + "\n"
	os.WriteFile(filepath.Join(dir, ".yars", "tokens.yaml"), []byte(toks), 0o600)
	var out bytes.Buffer
	if err := cmdMigrate([]string{"--data", dir}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "skip API token of zed: no such account") {
		t.Fatalf("output:\n%s", out.String())
	}
	d := openDB(t, dir)
	if u, ok, _ := d.TokenUser(strings.Repeat("ab", 32)); !ok || u != "bob" {
		t.Fatal("bob's token not migrated")
	}
	if items := legacyItems(dir); len(items) != 0 {
		t.Fatalf("still legacy: %v", items)
	}
}

func TestMigrateInterrupted(t *testing.T) {
	dir := legacyRepo(t)
	hook := filepath.Join(dir, ".git", "hooks", "pre-commit")
	os.MkdirAll(filepath.Dir(hook), 0o755)
	os.WriteFile(hook, []byte("#!/bin/sh\nexit 1\n"), 0o755)
	var out bytes.Buffer
	if err := cmdMigrate([]string{"--data", dir}, &out); err == nil {
		t.Fatal("migrate succeeded despite a failing commit")
	}
	if st, _ := exec.Command("git", "-C", dir, "status", "--porcelain", "--untracked-files=no").Output(); len(st) != 0 {
		t.Fatalf("tree left dirty:\n%s", st)
	}
	os.Remove(hook)
	if err := cmdMigrate([]string{"--data", dir}, &out); err != nil {
		t.Fatalf("re-run: %v\n%s", err, out.String())
	}
	r, _ := gitrepo.Open(dir)
	st := store.New(r, config.Default(), openDB(t, dir))
	if msgs, _ := st.Chat("acme", "F-001-sqli"); len(msgs) != 2 {
		t.Fatalf("chat after re-run: %d", len(msgs))
	}
}

// Migration finishes what an earlier run left half done: an engagement that
// is already its own repository but not registered in the main repo, and an
// engagement folder with no files at all.
func TestMigrateCompletesSplit(t *testing.T) {
	dir := legacyRepo(t)
	os.MkdirAll(filepath.Join(dir, "engagements", "empty", "findings"), 0o755)
	var out bytes.Buffer
	if err := cmdMigrate([]string{"--data", dir}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	// simulate an interrupted earlier run: acme is a repo but unregistered
	gitIn(dir, "rm", "-q", "--cached", "engagements/acme")
	gm, _ := os.ReadFile(filepath.Join(dir, ".gitmodules"))
	os.WriteFile(filepath.Join(dir, ".gitmodules"), []byte(strings.Replace(string(gm), store.SubmoduleEntry("acme"), "", 1)), 0o644)
	gitIn(dir, "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-qam", "lose acme")
	if items := legacyItems(dir); len(items) == 0 {
		t.Fatal("unregistered engagement not detected")
	}
	if err := cmdMigrate([]string{"--data", dir}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	r, _ := gitrepo.Open(dir)
	for _, e := range []string{"acme", "rt", "empty"} {
		if link, _ := r.Gitlink("HEAD", "engagements/"+e); link == "" {
			t.Errorf("%s not registered", e)
		}
	}
	if gm, _ := os.ReadFile(filepath.Join(dir, ".gitmodules")); !strings.Contains(string(gm), "url = ../e/acme") || !strings.Contains(string(gm), "ignore = all") {
		t.Fatalf(".gitmodules:\n%s", gm)
	}
	if st, _ := exec.Command("git", "-C", dir, "status", "--porcelain").Output(); len(st) != 0 {
		t.Fatalf("main repo dirty:\n%s", st)
	}
}

// serve refuses old data instead of silently showing every finding as draft.
func TestServeRefusesLegacyData(t *testing.T) {
	dir := legacyRepo(t)
	err := cmdServe([]string{"--data", dir, "--addr", "127.0.0.1:0"})
	if err == nil || !strings.Contains(err.Error(), "yars migrate") {
		t.Fatalf("err %v", err)
	}
}

// Accounts imported by yars migrate get the defaults v5 gave existing
// accounts: directors are admins and everyone is on the engagements that
// exist.
func TestMigrateAccountDefaults(t *testing.T) {
	dir := legacyRepo(t)
	hash := testHash(t, "pw")
	users := []config.User{{Username: "alice", Role: "pentester", PasswordHash: hash}, {Username: "bob", Role: "reviewer", PasswordHash: hash}, {Username: "dora", Role: "director", PasswordHash: hash}}
	if err := config.SaveUsers(dir, users); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdMigrate([]string{"--data", dir}, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	d := openDB(t, dir)
	if u, _, _ := d.User("dora"); !u.IsAdmin {
		t.Fatal("imported director is not an admin")
	}
	if u, _, _ := d.User("alice"); u.IsAdmin {
		t.Fatal("imported pentester is an admin")
	}
	for _, eng := range []string{"acme", "rt"} {
		if ok, _ := d.IsMember(eng, "alice"); !ok {
			t.Errorf("alice not on %s", eng)
		}
	}
}
