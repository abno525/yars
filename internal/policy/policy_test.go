package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/chat"
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

// fdir is the test finding, relative to the acme engagement repo.
const fdir = "findings/F-001-sqli"

type fx struct {
	t      *testing.T
	srv    *gitrepo.Repo // the main repo (data dir)
	st     *store.Store
	target string // "" = main repo, else the engagement repo pushes go to
	clone  string
	c      *Checker

	lastProblems []string
}

// repo is the server repo pushes currently go to.
func (f *fx) repo() *gitrepo.Repo {
	if f.target == "" {
		return f.srv
	}
	r, err := f.st.EngRepo(f.target)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

// on switches pushes to an engagement repo ("" = main) and clones it.
func (f *fx) on(target string) *fx {
	f.target = target
	f.reclone()
	return f
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
	d.AddMembers("acme", "alice", "pen2", "bob")
	f := &fx{t: t, srv: r, st: st, target: "acme", c: &Checker{Cfg: config.Default(), Users: users, DB: d}}
	f.reclone()
	return f
}

// An archived engagement takes no pushes; disabled accounts and accounts
// off the team push nothing.
func TestPolicyArchiveTeamDisabled(t *testing.T) {
	f := newFx(t)
	edit := func(d string) { write(d, fdir+"/attachments/a.txt", "x") }
	f.st.Archive("acme", user("dora"))
	if ps := f.push("dora", edit); !has(ps, "archived") {
		t.Fatalf("push to archived engagement: %v", ps)
	}
	f.st.Unarchive("acme", user("dora"))
	f.reclone()
	f.st.RemoveMember("acme", "pen2", user("dora"))
	if ps := f.pushAs("pen2", "pen2", edit); !has(ps, "team") {
		t.Fatalf("non-member pushed: %v", ps)
	}
	f.reclone()
	saved := f.c.Users
	f.c.Users = []config.User{{Username: "alice", Role: "pentester", Disabled: true}}
	if ps := f.push("alice", edit); !has(ps, "disabled") {
		t.Fatalf("disabled account pushed: %v", ps)
	}
	f.c.Users = saved
	f.reclone()
	if ps := f.push("alice", edit); len(ps) != 0 {
		t.Fatalf("member push rejected: %v", ps)
	}
}

func (f *fx) reclone() {
	f.clone = filepath.Join(f.t.TempDir(), "c")
	if out, err := exec.Command("git", "clone", "-q", f.repo().Dir, f.clone).CombinedOutput(); err != nil {
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
	return f.check(u, git(f.t, f.clone, "rev-parse", "HEAD"))
}

// check returns the problems with pushing commit newRev (made in the clone) as u.
func (f *fx) check(u, newRev string) []string {
	f.t.Helper()
	srv := f.repo()
	git(f.t, srv.Dir, "fetch", "-q", "--no-recurse-submodules", f.clone, "+HEAD:refs/test/candidate")
	old, _ := srv.Head()
	branch, _ := srv.CurrentBranch()
	f.c.Repo, f.c.Eng, f.c.Carry = srv, f.target, nil
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
		write(d, "findings/"+dir+"/finding.md", "---\n"+meta+"---\n\n## Description\n\nx\n")
	}
}

func TestPolicyYarsDir(t *testing.T) {
	f := newFx(t).on("")
	if ps := f.push("alice", func(d string) { write(d, ".yars/rules/x.yaml", "[]\n") }); !has(ps, ".yars") {
		t.Fatalf("pentester changed .yars: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { write(d, ".yars/rules/x.yaml", "[]\n") }); len(ps) != 0 {
		t.Fatalf("director rejected: %v", ps)
	}
}

// A config.yaml the server could not load is refused: it would refuse every
// later push (the repair too) and stop the server from starting.
func TestPolicyConfigMustLoad(t *testing.T) {
	f := newFx(t).on("")
	for _, body := range []string{"severities: [x\n", "severities: [critical, high]\n", "cvss:\n  version: \"4.0\"\n"} {
		f.reclone()
		if ps := f.push("dora", func(d string) { write(d, ".yars/config.yaml", body) }); !has(ps, ".yars/config.yaml: ") {
			t.Errorf("config %q accepted: %v", body, ps)
		}
	}
	f.reclone()
	if ps := f.push("dora", func(d string) {
		write(d, ".yars/config.yaml", "severities: [critical, high, medium, low, info, extreme]\n")
	}); len(ps) != 0 {
		t.Fatalf("valid config refused: %v", ps)
	}
}

func TestPolicyServerFilesNeverPushed(t *testing.T) {
	for _, p := range []string{".yars/users.yaml", ".yars/tokens.yaml", ".yars/secret.key", ".yars/yars.db", ".yars/yars.db-wal"} {
		f := newFx(t).on("")
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
	if ps := f.push("alice", func(d string) { write(d, "engagement.yaml", "name: X\n") }); !has(ps, "engagement.yaml") {
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

// A withdrawn finding is locked like a complete one: only a director may
// change it by push (the author restores it first).
func TestPolicyWithdrawnLocked(t *testing.T) {
	f := newFx(t)
	if err := f.st.Transition("acme", "F-001-sqli", workflow.Withdraw, "duplicate", user("alice")); err != nil {
		t.Fatal(err)
	}
	edit := func(d string) {
		editMeta(d, func(fd *finding.Finding) { fd.SetSection("Impact", "late change") })
	}
	f.reclone()
	if ps := f.push("alice", edit); !has(ps, "withdrawn") {
		t.Fatalf("withdrawn edit accepted: %v", ps)
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

// A pushed new finding can't take the number of a deleted one: it would
// inherit that finding's status, reviewers and chat.
func TestPolicyDeletedIDNotReused(t *testing.T) {
	f := newFx(t)
	f.st.PostChat("acme", "F-001-sqli", chatMsg("old"), user("bob"))
	git(t, f.repo().Dir, "rm", "-rq", fdir)
	git(t, f.repo().Dir, "commit", "-qm", "director deletes F-001")
	f.reclone()
	if ps := f.push("alice", newFinding("F-001-new", "id: F-001\ntitle: New\nauthor: alice\n")); !has(ps, "F-001") || !has(ps, "deleted") {
		t.Fatalf("reused id accepted: %v", ps)
	}
	// a director renaming a folder keeps the id: allowed
	g := newFx(t)
	if ps := g.push("dora", func(d string) {
		os.Rename(filepath.Join(d, fdir), filepath.Join(d, "findings/F-001-renamed"))
	}); len(ps) != 0 {
		t.Fatalf("rename rejected: %v", ps)
	}
}

// A director's push to an approved finding keeps it approved: the hook
// carries the approval to the new content.
func TestPolicyDirectorEditCarriesApproval(t *testing.T) {
	f := newFx(t)
	st := f.st
	st.SetReviewers("acme", "F-001-sqli", []string{"bob"}, user("alice"))
	st.UpdateSeverity("acme", "F-001-sqli", "high", "", user("alice").GitAuthor())
	st.Transition("acme", "F-001-sqli", workflow.Submit, "", user("alice"))
	st.Transition("acme", "F-001-sqli", workflow.Clear, "", user("bob"))
	st.Transition("acme", "F-001-sqli", workflow.Approve, "", user("dora"))
	f.reclone()
	if ps := f.push("dora", func(d string) {
		editMeta(d, func(fd *finding.Finding) { fd.SetSection("Impact", "director polish") })
	}); len(ps) != 0 {
		t.Fatalf("director edit rejected: %v", ps)
	}
	if len(f.c.Carry) != 1 || f.c.Carry[0].Fid != "F-001" {
		t.Fatalf("carry %+v", f.c.Carry)
	}
}

func chatMsg(text string) chat.Message { return chat.Message{Text: text} }

// Findings live in engagement repos; the main repo holds settings only, and
// its engagement pointers are the server's.
func TestPolicyMainRepo(t *testing.T) {
	f := newFx(t).on("")
	if ps := f.push("dora", func(d string) {
		write(d, "engagements/nope/findings/F-001-x/finding.md", "---\nid: F-001\ntitle: X\nauthor: dora\n---\n")
	}); !has(ps, "/git/e/") {
		t.Fatalf("finding pushed to the main repo: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { write(d, ".gitmodules", "[submodule \"x\"]\n") }); !has(ps, "server") {
		t.Fatalf(".gitmodules pushed: %v", ps)
	}
	// moving an engagement pointer
	f.reclone()
	other := t.TempDir()
	git(t, other, "init", "-q")
	git(t, other, "commit", "-q", "--allow-empty", "-m", "x")
	sha := git(t, other, "rev-parse", "HEAD")
	// build the commit with plumbing (porcelain ignores submodules here)
	git(t, f.clone, "update-index", "--cacheinfo", "160000,"+sha+",engagements/acme")
	tree := git(t, f.clone, "write-tree")
	rev := git(t, f.clone, "-c", "user.name=dora", "-c", "user.email=dora@yars.local", "commit-tree", tree, "-p", "HEAD", "-m", "move pointer")
	if ps := f.check("dora", rev); !has(ps, "server") {
		t.Fatalf("pointer moved by push: %v", ps)
	}
}

func TestPolicyAttachmentNeedsFinding(t *testing.T) {
	f := newFx(t)
	if ps := f.push("alice", func(d string) { write(d, "findings/F-009-nope/attachments/a.png", "x") }); !has(ps, "finding") {
		t.Fatalf("attachment without finding: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { write(d, ".yars/config.yaml", "x: 1\n") }); !has(ps, "not allowed") {
		t.Fatalf("settings pushed into an engagement repo: %v", ps)
	}
}

func TestPolicyAuthorship(t *testing.T) {
	f := newFx(t)
	if ps := f.pushAs("alice", "dora", func(d string) { write(d, fdir+"/attachments/a.txt", "x") }); !has(ps, "dora") {
		t.Fatalf("forged author accepted: %v", ps)
	}
}

func TestPolicyGitattributes(t *testing.T) {
	f := newFx(t).on("")
	if ps := f.push("alice", func(d string) { write(d, ".gitattributes", "*.md -diff\n") }); !has(ps, ".gitattributes") {
		t.Fatalf("pentester changed .gitattributes: %v", ps)
	}
	f.on("acme")
	if ps := f.push("dora", func(d string) { write(d, fdir+"/attachments/.gitattributes", "x\n") }); len(ps) == 0 {
		t.Fatal("nested .gitattributes accepted")
	}
}

func TestPolicyUnparseableOld(t *testing.T) {
	f := newFx(t)
	write(f.repo().Dir, fdir+"/finding.md", "not a finding\n")
	git(t, f.repo().Dir, "commit", "-qam", "break")
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
	f.on("rt")
	path := filepath.Join("findings", "F-001-sqli", "finding.md")
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
	f.c.Repo = f.srv
	ps := f.c.Check("alice", []Update{{Old: "0000000000000000000000000000000000000000", New: old, Ref: "refs/heads/feature"}})
	if !has(ps, "refs/heads/feature") {
		t.Fatalf("other ref accepted: %v", ps)
	}
	if ps := f.c.Check("mallory", []Update{{Old: old, New: old, Ref: "refs/heads/main"}}); !has(ps, "unknown user") {
		t.Fatalf("unknown user: %v", ps)
	}
}
