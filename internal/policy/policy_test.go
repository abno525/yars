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
	edit(f.clone)
	git(f.t, f.clone, "add", "-A")
	git(f.t, f.clone, "commit", "-qm", "change", "--allow-empty")
	newRev := git(f.t, f.clone, "rev-parse", "HEAD")
	git(f.t, f.srv.Dir, "fetch", "-q", f.clone, "+HEAD:refs/test/candidate")
	old, _ := f.srv.Head()
	branch, _ := f.srv.CurrentBranch()
	return f.c.Check(u, []Update{{Old: old, New: newRev, Ref: branch}})
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
