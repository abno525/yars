package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"yars/internal/auth"
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
	hash, _ := auth.HashPassword("pw")
	files := map[string]string{
		".yars/config.yaml":                 "severities: [critical, high, medium, low, info]\n",
		".gitignore":                        ".yars/users.yaml\n.yars/tokens.yaml\n",
		".gitattributes":                    "*.png binary\nchat.jsonl merge=union\n",
		"engagements/acme/engagement.yaml":  "name: ACME\ntype: pentest\n",
		"engagements/acme/findings/F-001-sqli/finding.md": "---\nid: F-001\ntitle: SQLi\nstatus: verification\nseverity: high\nauthor: alice\nreviewers:\n    - bob\n    - carol\ncleared_by:\n    - bob\n---\n\n## Impact\n\nDB read.\n",
		"engagements/acme/findings/F-001-sqli/chat.jsonl": `{"id":"aaaaaaaaaaaa","ts":"2026-11-04T10:00:00Z","user":"bob","text":"PoC?","section":"Impact"}` + "\n" +
			`{"id":"bbbbbbbbbbbb","ts":"2026-11-04T10:05:00Z","user":"alice","event":"submit"}` + "\n",
		"engagements/acme/findings/F-002-xss/finding.md": "---\nid: F-002\ntitle: XSS\nstatus: draft\nauthor: alice\nreviewers: []\nreturned: {by: bob, reason: add steps}\n---\n\n## Impact\n\nx\n",
		"engagements/rt/engagement.yaml":                 "name: RT\ntype: retest\nsource: acme\n",
		"engagements/rt/findings/F-001-sqli/finding.md":  "---\nid: F-001\ntitle: SQLi\nstatus: draft\nauthor: alice\nretest: {source: acme/F-001-sqli, result: not_fixed}\n---\n\n## Impact\n\nx\n",
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

// serve refuses old data instead of silently showing every finding as draft.
func TestServeRefusesLegacyData(t *testing.T) {
	dir := legacyRepo(t)
	err := cmdServe([]string{"--data", dir, "--addr", "127.0.0.1:0"})
	if err == nil || !strings.Contains(err.Error(), "yars migrate") {
		t.Fatalf("err %v", err)
	}
}
