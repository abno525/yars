package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/chat"
	"yars/internal/config"
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
	st := store.New(r, config.Default())
	a := user("alice").GitAuthor()
	st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a)
	ref, err := st.CreateFinding("acme", "SQLi", a)
	if err != nil || ref.Dir != "F-001-sqli" {
		t.Fatalf("%v %s", err, ref.Dir)
	}
	f := &fx{t: t, srv: r, st: st, c: &Checker{Repo: r, Cfg: config.Default(), Users: users}}
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

func TestPolicyYarsDir(t *testing.T) {
	f := newFx(t)
	if ps := f.push("alice", func(d string) { write(d, ".yars/users.yaml", "- username: alice\n  role: admin\n") }); !has(ps, ".yars") {
		t.Fatalf("pentester changed .yars: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { write(d, ".yars/rules/x.yaml", "[]\n") }); len(ps) != 0 {
		t.Fatalf("director rejected: %v", ps)
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
	nf := func(dir, meta string) func(string) {
		return func(d string) {
			write(d, "engagements/acme/findings/"+dir+"/finding.md", "---\n"+meta+"---\n\n## Description\n\nx\n")
		}
	}
	if ps := f.push("alice", nf("F-002-xss", "id: F-002\ntitle: XSS\nstatus: verification\nauthor: alice\n")); !has(ps, "draft") {
		t.Fatalf("non-draft new finding: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", nf("F-002-xss", "id: F-003\ntitle: XSS\nstatus: draft\nauthor: alice\n")); !has(ps, "F-003") {
		t.Fatalf("id/dir mismatch: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", nf("F-001-dup", "id: F-001\ntitle: Dup\nstatus: draft\nauthor: alice\n")); !has(ps, "duplicate") {
		t.Fatalf("duplicate id: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", nf("F-002-xss", "id: F-002\ntitle: XSS\nstatus: draft\nauthor: alice\n")); len(ps) != 0 {
		t.Fatalf("valid new finding: %v", ps)
	}
}

func TestPolicyStatusAndClearance(t *testing.T) {
	f := newFx(t)
	// draft -> complete directly
	if ps := f.push("dora", func(d string) { editMeta(d, set("status", "complete")) }); !has(ps, "draft → complete") {
		t.Fatalf("skip to complete: %v", ps)
	}
	// submit failing the gate (no reviewers)
	f.reclone()
	if ps := f.push("alice", func(d string) { editMeta(d, set("status", "verification")) }); !has(ps, "reviewer") {
		t.Fatalf("gate: %v", ps)
	}
	// get to verification via the store
	st := f.st
	st.SetReviewers("acme", "F-001-sqli", []string{"bob"}, user("alice"))
	st.UpdateSeverity("acme", "F-001-sqli", "high", "", user("alice").GitAuthor())
	if err := st.Transition("acme", "F-001-sqli", workflow.Submit, "", user("alice")); err != nil {
		t.Fatal(err)
	}
	f.reclone()
	if ps := f.push("alice", func(d string) { editMeta(d, set("cleared_by", []string{"bob"})) }); !has(ps, "cleared_by") {
		t.Fatalf("alice cleared for bob: %v", ps)
	}
	f.reclone()
	if ps := f.push("bob", func(d string) { editMeta(d, set("cleared_by", []string{"bob"})) }); len(ps) != 0 {
		t.Fatalf("legit clear: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", func(d string) { editMeta(d, set("author", "pen2")) }); !has(ps, "author") {
		t.Fatalf("author change: %v", ps)
	}
}

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

func TestPolicyChatAppendOnly(t *testing.T) {
	f := newFx(t)
	f.push("alice", func(string) {}) // no-op
	line := func(id, u string) string {
		return `{"id":"` + id + `","ts":"2026-11-04T10:00:00Z","user":"` + u + `","text":"hi"}` + "\n"
	}
	// seed one message on the server
	if _, err := f.st.PostChat("acme", "F-001-sqli", chatMsg("seed"), user("bob")); err != nil {
		t.Fatal(err)
	}
	f.reclone()
	chat := fdir + "/chat.jsonl"
	if ps := f.push("alice", func(d string) { write(d, chat, line("aaaaaaaaaaaa", "alice")) }); !has(ps, "append-only") {
		t.Fatalf("rewrite accepted: %v", ps)
	}
	f.reclone()
	appendLine := func(l string) func(string) {
		return func(d string) {
			b, _ := os.ReadFile(filepath.Join(d, chat))
			write(d, chat, string(b)+l)
		}
	}
	if ps := f.push("alice", appendLine(line("bbbbbbbbbbbb", "bob"))); !has(ps, "bob") {
		t.Fatalf("impersonation accepted: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", appendLine(`{"id":"cccccccccccc","ts":"2026-11-04T10:00:00Z","user":"alice","event":"approve"}`+"\n")); !has(ps, "event") {
		t.Fatalf("event accepted: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", appendLine(line("dddddddddddd", "alice"))); len(ps) != 0 {
		t.Fatalf("own message rejected: %v", ps)
	}
}

func chatMsg(text string) chat.Message { return chat.Message{Text: text} }

func newFinding(dir, meta string) func(string) {
	return func(d string) {
		write(d, "engagements/acme/findings/"+dir+"/finding.md", "---\n"+meta+"---\n\n## Description\n\nx\n")
	}
}

// toVerification puts F-001 into verification with bob as reviewer via the store.
func (f *fx) toVerification() {
	f.t.Helper()
	st := f.st
	st.SetReviewers("acme", "F-001-sqli", []string{"bob"}, user("alice"))
	st.UpdateSeverity("acme", "F-001-sqli", "high", "", user("alice").GitAuthor())
	if err := st.Transition("acme", "F-001-sqli", workflow.Submit, "", user("alice")); err != nil {
		f.t.Fatal(err)
	}
	f.reclone()
}

func TestPolicyNewFindingForgedState(t *testing.T) {
	f := newFx(t)
	cases := map[string]string{
		"cleared_by": "id: F-002\ntitle: X\nstatus: draft\nauthor: alice\nreviewers: [bob]\ncleared_by: [bob]\n",
		"author":     "id: F-002\ntitle: X\nstatus: draft\nauthor: pen2\n",
		"returned":   "id: F-002\ntitle: X\nstatus: draft\nauthor: alice\nreturned: {by: bob, reason: x}\n",
		"reviewer":   "id: F-002\ntitle: X\nstatus: draft\nauthor: alice\nreviewers: [pen2]\n",
	}
	for want, meta := range cases {
		f.reclone()
		if ps := f.push("alice", newFinding("F-002-x", meta)); !has(ps, want) {
			t.Errorf("%s: %v", want, ps)
		}
	}
	f.reclone()
	if ps := f.push("alice", newFinding("F-002-x", "id: F-002\ntitle: X\nstatus: draft\nauthor: alice\nreviewers: [bob]\n")); len(ps) != 0 {
		t.Fatalf("valid new finding: %v", ps)
	}
}

func TestPolicyStaleClearance(t *testing.T) {
	f := newFx(t)
	f.toVerification()
	f.st.Transition("acme", "F-001-sqli", workflow.Clear, "", user("bob"))
	f.reclone()
	edit := func(d string) {
		editMeta(d, func(fd *finding.Finding) { fd.SetSection("Impact", "rewritten after review") })
	}
	if ps := f.push("alice", edit); !has(ps, "cleared_by") {
		t.Fatalf("edit kept stale clearance: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", func(d string) {
		edit(d)
		editMeta(d, set("cleared_by", nil))
	}); len(ps) != 0 {
		t.Fatalf("edit dropping clearance: %v", ps)
	}
	// return by push: must drop clearances and record who/why
	f.reclone()
	if ps := f.push("bob", func(d string) { editMeta(d, set("status", "draft")) }); !has(ps, "reason") {
		t.Fatalf("return without reason/clearing: %v", ps)
	}
	f.reclone()
	if ps := f.push("bob", func(d string) {
		editMeta(d, set("status", "draft"))
		editMeta(d, set("cleared_by", nil))
		editMeta(d, set("returned", finding.Returned{By: "bob", Reason: "needs PoC"}))
	}); len(ps) != 0 {
		t.Fatalf("valid return: %v", ps)
	}
}

// A director may review by push without being assigned: they add themselves
// to reviewers and cleared_by in one push, and nothing else may change.
func TestPolicyDirectorClearsUnassigned(t *testing.T) {
	f := newFx(t)
	f.toVerification()
	f.reclone()
	selfClear := func(d string) {
		editMeta(d, set("reviewers", []string{"bob", "dora"}))
		editMeta(d, set("cleared_by", []string{"dora"}))
	}
	if ps := f.push("dora", selfClear); len(ps) != 0 {
		t.Fatalf("director self-review rejected: %v", ps)
	}
	// clearing must not ride along with any other reviewer change
	f = newFx(t)
	f.toVerification()
	f.reclone()
	if ps := f.push("dora", func(d string) {
		editMeta(d, set("reviewers", []string{"dora"}))
		editMeta(d, set("cleared_by", []string{"dora"}))
	}); !has(ps, "cleared_by") {
		t.Fatalf("clear plus reviewer swap accepted: %v", ps)
	}
}

func TestPolicyEngagementMustExist(t *testing.T) {
	f := newFx(t)
	if ps := f.push("alice", func(d string) {
		write(d, "engagements/ghost/findings/F-001-x/finding.md", "---\nid: F-001\ntitle: X\nstatus: draft\nauthor: alice\n---\n")
	}); !has(ps, "engagement") {
		t.Fatalf("finding in missing engagement: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", func(d string) { write(d, "engagements/acme/findings/F-009-nope/chat.jsonl", "") }); !has(ps, "finding") {
		t.Fatalf("chat for missing finding: %v", ps)
	}
}

func TestPolicyReviewerValidity(t *testing.T) {
	f := newFx(t)
	for _, r := range []string{"ghost", "pen2", "alice"} {
		f.reclone()
		if ps := f.push("alice", func(d string) { editMeta(d, set("reviewers", []string{r})) }); !has(ps, r) {
			t.Errorf("reviewer %s accepted: %v", r, ps)
		}
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
	good := "---\nid: F-001\ntitle: X\nstatus: complete\nauthor: alice\n---\n"
	if ps := f.push("alice", func(d string) { write(d, fdir+"/finding.md", good) }); !has(ps, "director") {
		t.Fatalf("fix of broken finding by pentester: %v", ps)
	}
}

func TestPolicySymlinkAndSeverity(t *testing.T) {
	f := newFx(t)
	if ps := f.push("alice", func(d string) { os.Symlink("../../../../.git/config", filepath.Join(d, fdir, "chat.jsonl")) }); !has(ps, "regular file") {
		t.Fatalf("symlink accepted: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", func(d string) { editMeta(d, set("severity", "banana")) }); !has(ps, "banana") {
		t.Fatalf("bad severity accepted: %v", ps)
	}
}

func TestPolicyRetestField(t *testing.T) {
	f := newFx(t)
	if err := f.st.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{"F-001-sqli"}, "", user("dora")); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("engagements", "rt", "findings", "F-001-sqli", "finding.md")
	edit := func(fn func(*finding.Finding)) func(string) {
		return func(d string) {
			b, _ := os.ReadFile(filepath.Join(d, path))
			fd, _ := finding.Parse(b)
			fn(fd)
			os.WriteFile(filepath.Join(d, path), fd.Bytes(), 0o644)
		}
	}
	cases := map[string]func(*finding.Finding){
		"removed": func(fd *finding.Finding) { fd.SetMeta("retest", nil) },
		"source":  func(fd *finding.Finding) { fd.SetMeta("retest", finding.Retest{Source: "acme/F-009-x"}) },
		"banana": func(fd *finding.Finding) {
			fd.SetMeta("retest", finding.Retest{Source: "acme/F-001-sqli", Result: "banana"})
		},
	}
	for name, fn := range cases {
		f.reclone()
		if ps := f.push("alice", edit(fn)); !has(ps, "retest") {
			t.Errorf("%s accepted: %v", name, ps)
		}
	}
	// a normal finding can't gain a retest block
	f.reclone()
	if ps := f.push("alice", func(d string) { editMeta(d, set("retest", finding.Retest{Source: "x/F-001"})) }); !has(ps, "retest") {
		t.Errorf("retest added: %v", ps)
	}
	// a pentester can't push a new finding carrying a retest block
	f.reclone()
	if ps := f.push("alice", newFinding("F-002-x", "id: F-002\ntitle: X\nstatus: draft\nauthor: alice\nretest: {source: acme/F-001-sqli, result: fixed}\n")); !has(ps, "retest") {
		t.Errorf("new finding with retest accepted: %v", ps)
	}
}

func TestRetestPolicyCompatible(t *testing.T) {
	f := newFx(t)
	if err := f.st.CreateRetest(store.Engagement{ID: "rt", Name: "RT"}, "acme", []string{"F-001-sqli"}, "", user("dora")); err != nil {
		t.Fatal(err)
	}
	f.reclone()
	path := filepath.Join("engagements", "rt", "findings", "F-001-sqli", "finding.md")
	ps := f.push("alice", func(d string) {
		b, _ := os.ReadFile(filepath.Join(d, path))
		fd, _ := finding.Parse(b)
		fd.SetMeta("retest", finding.Retest{Source: "acme/F-001-sqli", Result: "fixed"})
		os.WriteFile(filepath.Join(d, path), fd.Bytes(), 0o644)
	})
	if len(ps) != 0 {
		t.Fatalf("retest result push rejected: %v", ps)
	}
}

func TestPolicyUsersFileNeverPushed(t *testing.T) {
	f := newFx(t)
	if ps := f.push("dora", func(d string) { write(d, ".yars/users.yaml", "[]\n") }); !has(ps, "users") {
		t.Fatalf("users.yaml pushed: %v", ps)
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
