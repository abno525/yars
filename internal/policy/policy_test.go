package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/store"
	"yars/internal/workflow"
)

var users = []config.User{
	{Username: "alice", Role: "pentester"},
	{Username: "pen2", Role: "pentester"},
	{Username: "bob", Role: "reviewer"},
	{Username: "dora", Role: "director"},
}

func user(n string) config.User {
	for _, u := range users {
		if u.Username == n {
			return u
		}
	}
	return config.User{}
}

const fdir = "engagements/acme/findings/F-001-sqli"

type fx struct {
	t     *testing.T
	srv   *gitrepo.Repo
	st    *store.Store
	clone string
	c     *Checker

	lastProblems []string
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=x", "-c", "user.email=x@x", "-c", "commit.gpgsign=false"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func newFx(t *testing.T) *fx {
	t.Helper()
	r, err := gitrepo.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	st := store.New(r, config.Default(), d)
	a := user("alice").GitAuthor()
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a)
	ref, err := st.CreateFinding("acme", "SQLi", a)
	if err != nil || ref.Dir != "F-001-sqli" {
		t.Fatalf("%v %s", err, ref.Dir)
	}
	f := &fx{t: t, srv: r, st: st, c: &Checker{Repo: r, Cfg: config.Default(), Users: users, DB: d}}
	f.reclone()
	return f
}

func (f *fx) reclone() {
	f.clone = filepath.Join(f.t.TempDir(), "c")
	if out, err := exec.Command("git", "clone", "-q", f.srv.Dir, f.clone).CombinedOutput(); err != nil {
		f.t.Fatalf("clone: %v %s", err, out)
	}
}

// push commits edit in the clone and returns problems for pushing it as u.
func (f *fx) push(u string, edit func(dir string)) []string {
	f.t.Helper()
	f.pushAs(u, u, edit)
	return f.lastProblems
}

// pushAs commits as git author `as` and checks the push as user u.
func (f *fx) pushAs(u, as string, edit func(dir string)) []string {
	f.t.Helper()
	edit(f.clone)
	git(f.t, f.clone, "add", "-A")
	git(f.t, f.clone, "-c", "user.name="+as, "-c", "user.email="+as+"@yars.local", "commit", "-qm", "change", "--allow-empty")
	newRev := git(f.t, f.clone, "rev-parse", "HEAD")
	git(f.t, f.srv.Dir, "fetch", "-q", f.clone, "+HEAD:refs/test/candidate")
	old, _ := f.srv.Head()
	branch, _ := f.srv.CurrentBranch()
	f.lastProblems = f.c.Check(u, []Update{{Old: old, New: newRev, Ref: branch}})
	return f.lastProblems
}

func write(dir, rel, body string) {
	os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755)
	os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644)
}

func editMeta(dir string, fn func(f *finding.Finding)) {
	p := filepath.Join(dir, fdir, "finding.md")
	b, _ := os.ReadFile(p)
	f, err := finding.Parse(b)
	if err != nil {
		panic(err)
	}
	fn(f)
	os.WriteFile(p, f.Bytes(), 0o644)
}

func set(k string, v any) func(*finding.Finding) {
	return func(f *finding.Finding) { f.SetMeta(k, v) }
}

func has(ps []string, sub string) bool {
	return strings.Contains(strings.Join(ps, "\n"), sub)
}

func newFinding(dir, meta string) func(string) {
	return func(d string) {
		write(d, "engagements/acme/findings/"+dir+"/finding.md", "---\n"+meta+"---\n\n## Description\n\nx\n")
	}
}

func TestPolicyYarsDir(t *testing.T) {
	f := newFx(t)
	if ps := f.push("alice", func(d string) { write(d, ".yars/rules/x.yaml", "[]\n") }); !has(ps, ".yars") {
		t.Fatalf("pentester changed .yars: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { write(d, ".yars/rules/x.yaml", "[]\n") }); len(ps) != 0 {
		t.Fatalf("director rejected: %v", ps)
	}
}

func TestPolicyServerFilesNeverPushed(t *testing.T) {
	for _, p := range []string{".yars/users.yaml", ".yars/tokens.yaml", ".yars/yars.db", ".yars/yars.db-wal"} {
		f := newFx(t)
		if ps := f.push("dora", func(d string) { write(d, p, "x\n") }); !has(ps, "server") {
			t.Errorf("%s pushed: %v", p, ps)
		}
	}
}

func TestPolicyPaths(t *testing.T) {
	f := newFx(t)
	if ps := f.push("alice", func(d string) { write(d, "random.txt", "x") }); !has(ps, "random.txt") {
		t.Fatalf("stray file accepted: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", func(d string) { write(d, fdir+"/attachments/shot.png", "png") }); len(ps) != 0 {
		t.Fatalf("attachment rejected: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", func(d string) { write(d, "engagements/acme/engagement.yaml", "name: X\n") }); !has(ps, "engagement.yaml") {
		t.Fatalf("pentester changed engagement: %v", ps)
	}
}

func TestPolicyNewFinding(t *testing.T) {
	f := newFx(t)
	if ps := f.push("alice", newFinding("F-002-xss", "id: F-003\ntitle: XSS\nauthor: alice\n")); !has(ps, "F-003") {
		t.Fatalf("id/dir mismatch: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", newFinding("F-001-dup", "id: F-001\ntitle: Dup\nauthor: alice\n")); !has(ps, "duplicate") {
		t.Fatalf("duplicate id: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", newFinding("F-002-xss", "id: F-002\ntitle: XSS\nauthor: pen2\n")); !has(ps, "author") {
		t.Fatalf("someone else's finding: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", newFinding("F-002-xss", "id: F-002\ntitle: XSS\nauthor: alice\n")); len(ps) != 0 {
		t.Fatalf("valid new finding: %v", ps)
	}
}

// Workflow state lives in the YARS database; a push can't carry it, in a
// new finding or an existing one.
func TestPolicyStateKeysRejected(t *testing.T) {
	f := newFx(t)
	if ps := f.push("alice", newFinding("F-002-xss", "id: F-002\ntitle: XSS\nstatus: complete\nauthor: alice\n")); !has(ps, "managed in YARS") {
		t.Fatalf("new finding with status: %v", ps)
	}
	cases := map[string]any{
		"status":     "complete",
		"reviewers":  []string{"bob"},
		"cleared_by": []string{"bob"},
		"returned":   finding.Returned{By: "bob", Reason: "x"},
		"retest":     finding.Retest{Source: "x/F-001", Result: "fixed"},
	}
	for k, v := range cases {
		f.reclone()
		if ps := f.push("dora", func(d string) { editMeta(d, set(k, v)) }); !has(ps, "managed in YARS") || !has(ps, k) {
			t.Errorf("%s pushed: %v", k, ps)
		}
	}
	f.reclone()
	if ps := f.push("alice", func(d string) { editMeta(d, set("author", "pen2")) }); !has(ps, "author") {
		t.Fatalf("author change: %v", ps)
	}
}

// Chat lives in the database; chat.jsonl files are not accepted any more.
func TestPolicyChatFileRejected(t *testing.T) {
	f := newFx(t)
	line := `{"id":"aaaaaaaaaaaa","ts":"2026-11-04T10:00:00Z","user":"alice","text":"hi"}` + "\n"
	if ps := f.push("alice", func(d string) { write(d, fdir+"/chat.jsonl", line) }); !has(ps, "chat") {
		t.Fatalf("chat file accepted: %v", ps)
	}
}

// The lock is judged on the state in the database: once approved, only a
// director may change the content by push.
func TestPolicyLockedEdit(t *testing.T) {
	f := newFx(t)
	st := f.st
	st.SetReviewers("acme", "F-001-sqli", []string{"bob"}, user("alice"))
	st.UpdateSeverity("acme", "F-001-sqli", "high", "", user("alice").GitAuthor())
	st.Transition("acme", "F-001-sqli", workflow.Submit, "", user("alice"))
	st.Transition("acme", "F-001-sqli", workflow.Clear, "", user("bob"))
	if err := st.Transition("acme", "F-001-sqli", workflow.Approve, "", user("dora")); err != nil {
		t.Fatal(err)
	}
	edit := func(d string) {
		editMeta(d, func(fd *finding.Finding) { fd.SetSection("Impact", "late change") })
	}
	f.reclone()
	if ps := f.push("alice", edit); !has(ps, "complete") {
		t.Fatalf("locked edit accepted: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", edit); len(ps) != 0 {
		t.Fatalf("director edit rejected: %v", ps)
	}
}

// A content edit during review is accepted; the reviewer's clearance simply
// stops counting (it was given for the old content).
func TestPolicyEditDuringReview(t *testing.T) {
	f := newFx(t)
	st := f.st
	st.SetReviewers("acme", "F-001-sqli", []string{"bob"}, user("alice"))
	st.UpdateSeverity("acme", "F-001-sqli", "high", "", user("alice").GitAuthor())
	st.Transition("acme", "F-001-sqli", workflow.Submit, "", user("alice"))
	st.Transition("acme", "F-001-sqli", workflow.Clear, "", user("bob"))
	f.reclone()
	if ps := f.push("alice", func(d string) {
		editMeta(d, func(fd *finding.Finding) { fd.SetSection("Impact", "changed") })
	}); len(ps) != 0 {
		t.Fatalf("edit during review rejected: %v", ps)
	}
}

func TestPolicyEngagementMustExist(t *testing.T) {
	f := newFx(t)
	if ps := f.push("alice", func(d string) {
		write(d, "engagements/nope/findings/F-001-x/finding.md", "---\nid: F-001\ntitle: X\nauthor: alice\n---\n")
	}); !has(ps, "engagement") {
		t.Fatalf("finding in unknown engagement: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", func(d string) { write(d, "engagements/acme/findings/F-009-nope/attachments/a.png", "x") }); !has(ps, "finding") {
		t.Fatalf("attachment without finding: %v", ps)
	}
}

func TestPolicyAuthorship(t *testing.T) {
	f := newFx(t)
	if ps := f.pushAs("alice", "dora", func(d string) { write(d, fdir+"/attachments/a.txt", "x") }); !has(ps, "dora") {
		t.Fatalf("forged author accepted: %v", ps)
	}
}

func TestPolicyGitattributes(t *testing.T) {
	f := newFx(t)
	if ps := f.push("alice", func(d string) { write(d, ".gitattributes", "*.md -diff\n") }); !has(ps, ".gitattributes") {
		t.Fatalf("pentester changed .gitattributes: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { write(d, fdir+"/attachments/.gitattributes", "x\n") }); len(ps) == 0 {
		t.Fatal("nested .gitattributes accepted")
	}
}

func TestPolicyUnparseableOld(t *testing.T) {
	f := newFx(t)
	write(f.srv.Dir, fdir+"/finding.md", "not a finding\n")
	git(t, f.srv.Dir, "commit", "-qam", "break")
	f.reclone()
	good := "---\nid: F-001\ntitle: X\nauthor: alice\n---\n"
	if ps := f.push("alice", func(d string) { write(d, fdir+"/finding.md", good) }); !has(ps, "director") {
		t.Fatalf("fix of broken finding by pentester: %v", ps)
	}
}

func TestPolicySymlinkAndSeverity(t *testing.T) {
	f := newFx(t)
	if ps := f.push("alice", func(d string) { os.Symlink("../../../../.git/config", filepath.Join(d, fdir, "attachments-link")) }); !has(ps, "regular file") {
		t.Fatalf("symlink accepted: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", func(d string) { editMeta(d, set("severity", "banana")) }); !has(ps, "banana") {
		t.Fatalf("bad severity accepted: %v", ps)
	}
}

// Content of a retest finding is edited like any other; its retest link and
// result are in the database.
func TestRetestContentPush(t *testing.T) {
	f := newFx(t)
	if err := f.st.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{"F-001-sqli"}, "", user("dora")); err != nil {
		t.Fatal(err)
	}
	f.reclone()
	path := filepath.Join("engagements", "rt", "findings", "F-001-sqli", "finding.md")
	ps := f.push("alice", func(d string) {
		b, _ := os.ReadFile(filepath.Join(d, path))
		fd, _ := finding.Parse(b)
		fd.SetSection("Impact", "still exploitable")
		os.WriteFile(filepath.Join(d, path), fd.Bytes(), 0o644)
	})
	if len(ps) != 0 {
		t.Fatalf("retest content push rejected: %v", ps)
	}
}

func TestPolicyOtherRef(t *testing.T) {
	f := newFx(t)
	old, _ := f.srv.Head()
	ps := f.c.Check("alice", []Update{{Old: "0000000000000000000000000000000000000000", New: old, Ref: "refs/heads/feature"}})
	if !has(ps, "refs/heads/feature") {
		t.Fatalf("other ref accepted: %v", ps)
	}
	if ps := f.c.Check("mallory", []Update{{Old: old, New: old, Ref: "refs/heads/main"}}); !has(ps, "unknown user") {
		t.Fatalf("unknown user: %v", ps)
	}
}
