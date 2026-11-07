package policy

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
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

// hasLine reports whether one problem starts with prefix and contains sub.
func hasLine(ps []string, prefix, sub string) bool {
	return slices.ContainsFunc(ps, func(p string) bool { return strings.HasPrefix(p, prefix) && strings.Contains(p, sub) })
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
	f.reclone()
	if ps := f.push("dora", func(d string) {
		os.RemoveAll(filepath.Join(d, ".yars", "config.yaml"))
		write(d, ".yars/config.yaml/x", "x\n")
	}); !has(ps, "must be a file") {
		t.Fatalf("config.yaml as a directory accepted: %v", ps)
	}
}

// The main repo's .gitignore is a director's to change.
func TestPolicyGitignore(t *testing.T) {
	f := newFx(t).on("")
	if ps := f.push("alice", func(d string) { write(d, ".gitignore", "*.tmp\n") }); !has(ps, "only a director can change .gitignore") {
		t.Fatalf("pentester: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { write(d, ".gitignore", "*.tmp\n") }); len(ps) != 0 {
		t.Fatalf("director refused: %v", ps)
	}
}

// A section name used twice is refused: only the first body can be shown
// or edited, and both would ship in exports.
func TestPolicyDuplicateSection(t *testing.T) {
	f := newFx(t)
	ps := f.push("alice", func(d string) {
		p := filepath.Join(d, fdir, "finding.md")
		b, _ := os.ReadFile(p)
		os.WriteFile(p, append(b, []byte("\n## Impact\n\nsecond impact\n")...), 0o644)
	})
	if !has(ps, "section Impact appears twice") {
		t.Fatalf("duplicate section accepted: %v", ps)
	}
}

// The same holds for a template: every finding made from it would take
// the duplicated section.
func TestPolicyDuplicateSectionTemplate(t *testing.T) {
	f := newFx(t).on("")
	tpl := "---\ntitle: SQLi\n---\n\n## Impact\n\nfirst\n\n## Impact\n\nsecond\n"
	if ps := f.push("dora", func(d string) { write(d, ".yars/templates/sqli.md", tpl) }); !has(ps, "section Impact appears twice") {
		t.Fatalf("template with a duplicate section accepted: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { write(d, ".yars/templates/sqli.md", "---\ntitle: SQLi\n---\n\n## Impact\n\nfirst\n") }); len(ps) != 0 {
		t.Fatalf("valid template refused: %v", ps)
	}
}

// A path outside the layout is explained in the pushed repository's own
// terms, not the server's data-dir paths.
func TestPolicyOutsideMessagePerRepo(t *testing.T) {
	f := newFx(t)
	ps := f.push("alice", func(d string) { write(d, "findings/README.md", "x\n") })
	if !has(ps, "findings/README.md: not allowed here; findings must live under findings/<finding>/") || has(ps, "engagements/<engagement>") {
		t.Fatalf("engagement repo: %v", ps)
	}
	f.on("")
	ps = f.push("dora", func(d string) { write(d, "notes.txt", "x\n") })
	if !has(ps, "notes.txt: not allowed here; this repository holds settings (.yars)") || has(ps, "engagements/<engagement>") {
		t.Fatalf("main repo: %v", ps)
	}
}

// engagement.yaml must parse and cannot be deleted: either makes the
// engagement fail (500) or vanish from YARS.
func TestPolicyEngagementYAML(t *testing.T) {
	f := newFx(t)
	if ps := f.push("dora", func(d string) { write(d, "engagement.yaml", "name: [x\n") }); !has(ps, "engagement.yaml: cannot parse") {
		t.Fatalf("broken engagement.yaml accepted: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { os.Remove(filepath.Join(d, "engagement.yaml")) }); !has(ps, "cannot be deleted") {
		t.Fatalf("engagement.yaml deletion accepted: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { write(d, "engagement.yaml", "name: ACME Corp\ntype: pentest\n") }); len(ps) != 0 {
		t.Fatalf("valid engagement.yaml refused: %v", ps)
	}
}

// engagement.yaml is held to the engagement Settings tab's rules, and its
// type and source stay as created (a pentest can't become a retest of
// another engagement, whose findings its team would then read).
func TestPolicyEngagementValues(t *testing.T) {
	f := newFx(t)
	cases := map[string]string{
		"name: \"\"\ntype: pentest\n":                                     "name is required",
		"name: ACME\ntype: pentest\nstart: 2026-13-01\n":                  "YYYY-MM-DD",
		"name: ACME\ntype: pentest\nstart: 2026-11-07\nend: 2026-11-01\n": "end is before the start",
		"name: ACME\nclient: \"a\\nb\"\ntype: pentest\n":                  "client must be one line",
		"name: ACME\ntype: retest\nsource: secret\n":                      "keep type: pentest",
		"name: ACME\ntype: pentest\nsource: secret\n":                     "keep source: \"\"",
		"name: ACME\n": "keep type: pentest",
	}
	for body, want := range cases {
		f.reclone()
		ps := f.push("dora", func(d string) { write(d, "engagement.yaml", body) })
		if !hasLine(ps, "commit "+short(t, f.clone, "HEAD")+" engagement.yaml: ", want) {
			t.Errorf("%q: %v", body, ps)
		}
	}
}

// When the server's own config does not load, only a director's push that
// changes it to one that loads is accepted.
func TestPolicyBrokenConfigRepair(t *testing.T) {
	f := newFx(t).on("")
	f.c.ConfigErr = errors.New("yaml: line 1: did not find expected ',' or ']'")
	if ps := f.push("dora", func(d string) { write(d, ".yars/rules/x.yaml", "[]\n") }); !has(ps, "cannot be loaded") {
		t.Fatalf("unrelated push accepted while the config is broken: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { write(d, ".yars/config.yaml", "severities: [x\n") }); !has(ps, "cannot load") {
		t.Fatalf("broken repair accepted: %v", ps)
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { write(d, ".yars/config.yaml", "sections: [Description]\n") }); len(ps) != 0 {
		t.Fatalf("repair refused: %v", ps)
	}
	f.on("acme")
	if ps := f.push("alice", func(d string) { write(d, fdir+"/attachments/a.txt", "x") }); !has(ps, "cannot be loaded") {
		t.Fatalf("engagement push accepted while the config is broken: %v", ps)
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

// A finding in verification is locked against pushes except by its
// assigned reviewers and directors: the author is refused (naming who may
// change it), its attachments too; a reviewer's edit is accepted and the
// clearance simply stops counting (it was given for the old content).
func TestPolicyEditDuringReview(t *testing.T) {
	f := newFx(t)
	st := f.st
	st.SetReviewers("acme", "F-001-sqli", []string{"bob"}, user("alice"))
	st.UpdateSeverity("acme", "F-001-sqli", "high", "", user("alice").GitAuthor())
	st.Transition("acme", "F-001-sqli", workflow.Submit, "", user("alice"))
	st.Transition("acme", "F-001-sqli", workflow.Clear, "", user("bob"))
	edit := func(d string) { editMeta(d, func(fd *finding.Finding) { fd.SetSection("Impact", "changed") }) }
	f.reclone()
	if ps := f.push("alice", edit); !hasLine(ps, "commit "+short(t, f.clone, "HEAD")+" "+fdir+"/finding.md: ", "F-001 is in verification; only its reviewers (bob) and directors can change it") {
		t.Fatalf("author's edit in verification: %v", ps)
	}
	f.reclone()
	if ps := f.push("pen2", func(d string) { write(d, fdir+"/attachments/new.txt", "x") }); !has(ps, "F-001 is in verification") {
		t.Fatalf("attachment added to a finding in verification: %v", ps)
	}
	for _, who := range []string{"bob", "dora"} {
		f.reclone()
		if ps := f.push(who, edit); len(ps) != 0 {
			t.Fatalf("%s's edit in verification rejected: %v", who, ps)
		}
	}
}

// The attachments of an approved finding are locked like its text.
func TestPolicyLockedAttachments(t *testing.T) {
	f := newFx(t)
	write(f.repo().Dir, fdir+"/attachments/shot.png", "png")
	git(t, f.repo().Dir, "add", "-A")
	git(t, f.repo().Dir, "commit", "-qm", "shot")
	f.st.DB().Tx(func(tx *db.Tx) error { return tx.PutState("acme", "F-001", db.State{Status: "reported"}) })
	for name, edit := range map[string]func(string){
		"replace": func(d string) { write(d, fdir+"/attachments/shot.png", "other") },
		"delete":  func(d string) { os.Remove(filepath.Join(d, fdir, "attachments", "shot.png")) },
		"add":     func(d string) { write(d, fdir+"/attachments/more.png", "x") },
	} {
		f.reclone()
		if ps := f.push("alice", edit); !has(ps, "F-001 is reported; only a director can change it") {
			t.Errorf("%s: %v", name, ps)
		}
	}
	f.reclone()
	if ps := f.push("dora", func(d string) { write(d, fdir+"/attachments/shot.png", "other") }); len(ps) != 0 {
		t.Fatalf("director refused: %v", ps)
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

// short is the 7-hex name of rev in dir.
func short(t *testing.T, dir, rev string) string {
	return git(t, dir, "rev-parse", "--short=7", rev)
}

const crit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" // 9.8 critical

// A pushed finding is held to the website's rules for what it changes:
// CVSS vector and version, severity agreeing with the vector, assets and
// title; each refusal names the commit, the file and the rule.
func TestPolicyFindingContent(t *testing.T) {
	f := newFx(t)
	cases := []struct {
		edit func(*finding.Finding)
		want string
	}{
		{set("cvss", "garbage"), "CVSS vector garbage: "},
		{func(fd *finding.Finding) {
			fd.SetMeta("cvss", "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
			fd.SetMeta("severity", "critical")
		}, "write " + crit},
		{func(fd *finding.Finding) { fd.SetMeta("cvss", crit); fd.SetMeta("severity", "low") }, "severity low does not match the CVSS vector (score 9.8 is critical)"},
		{set("cvss", crit), "severity (none) does not match"},
		{set("assets", []finding.Asset{{Host: "h", Port: "70000"}}), "asset 1: port must be 1–65535"},
		{set("assets", []finding.Asset{{URL: "example.com/x"}}), "asset 1: URL needs a scheme and host"},
		{set("assets", []finding.Asset{{Host: "h", Note: "a\nb"}}), "asset 1: one line"},
		{set("title", ""), "the title must be one line"},
		{set("title", "two\nlines"), "the title must be one line"},
		{set("title", "Upload ‮gnp.exe"), "hidden text-direction characters"},
	}
	for _, c := range cases {
		f.reclone()
		ps := f.push("alice", func(d string) { editMeta(d, c.edit) })
		if !hasLine(ps, "commit "+short(t, f.clone, "HEAD")+" "+fdir+"/finding.md: ", c.want) {
			t.Errorf("want %q in %v", c.want, ps)
		}
	}
	f.reclone()
	if ps := f.push("alice", func(d string) {
		editMeta(d, func(fd *finding.Finding) { fd.SetMeta("cvss", crit); fd.SetMeta("severity", "critical") })
	}); len(ps) != 0 {
		t.Fatalf("valid CVSS refused: %v", ps)
	}
}

// A problem the server copy already has does not block an edit of another
// part (the website lets that edit through too); changing the bad part
// itself is checked.
func TestPolicyGrandfathered(t *testing.T) {
	f := newFx(t)
	editMeta(f.repo().Dir, set("cvss", "CVSS:3.1/AV:N"))
	git(t, f.repo().Dir, "commit", "-qam", "old push without checks")
	f.reclone()
	if ps := f.push("alice", func(d string) {
		editMeta(d, func(fd *finding.Finding) { fd.SetSection("Description", "better words") })
	}); len(ps) != 0 {
		t.Fatalf("edit of another part refused: %v", ps)
	}
	f.reclone()
	if ps := f.push("alice", func(d string) { editMeta(d, set("cvss", "CVSS:3.1/AV:L")) }); !has(ps, "CVSS vector") {
		t.Fatalf("changed bad vector accepted: %v", ps)
	}
}

// Every pushed commit is checked, not only the last: a broken middle
// commit is named even when a later one repairs it.
func TestPolicyEveryCommit(t *testing.T) {
	f := newFx(t)
	commit := func(edit func(string)) string {
		edit(f.clone)
		git(t, f.clone, "add", "-A")
		git(t, f.clone, "-c", "user.name=alice", "-c", "user.email=alice@yars.local", "commit", "-qm", "step")
		return short(t, f.clone, "HEAD")
	}
	c1 := commit(func(d string) { editMeta(d, func(fd *finding.Finding) { fd.SetSection("Impact", "one") }) })
	c2 := commit(func(d string) { editMeta(d, set("cvss", "garbage")) })
	c3 := commit(func(d string) { editMeta(d, set("cvss", nil)) })
	ps := f.check("alice", git(t, f.clone, "rev-parse", "HEAD"))
	if !has(ps, "commit "+c2+" "+fdir+"/finding.md: CVSS vector garbage") || has(ps, c1) || has(ps, c3) {
		t.Fatalf("middle commit: %v", ps)
	}
}

// A merge brings a side branch's commits along: those are checked one by
// one, and the merge itself only for what it changes beyond both sides.
func TestPolicyMergeSideBranch(t *testing.T) {
	f := newFx(t)
	as := []string{"-c", "user.name=alice", "-c", "user.email=alice@yars.local"}
	run := func(args ...string) { git(t, f.clone, append(slices.Clone(as), args...)...) }
	run("switch", "-qc", "side")
	write(f.clone, fdir+"/attachments/tool.txt", "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	run("add", "-A")
	run("commit", "-qm", "side: binary")
	bad := short(t, f.clone, "HEAD")
	run("rm", "-q", fdir+"/attachments/tool.txt")
	run("commit", "-qm", "side: drop it")
	run("switch", "-q", "-")
	editMeta(f.clone, func(fd *finding.Finding) { fd.SetSection("Impact", "main work") })
	run("commit", "-qam", "main work")
	run("merge", "-q", "--no-edit", "side")
	ps := f.check("alice", git(t, f.clone, "rev-parse", "HEAD"))
	if !has(ps, "commit "+bad+" "+fdir+"/attachments/tool.txt: only images and text files can be attached") || len(ps) != 1 {
		t.Fatalf("side branch: %v", ps)
	}
}

// mergeOf makes a merge commit in the clone with parents HEAD and other,
// whose tree is HEAD's with rel taken from other, authored as as.
func (f *fx) mergeOf(as, other, rel string) string {
	cr, err := gitrepo.Open(f.clone)
	if err != nil {
		f.t.Fatal(err)
	}
	b, err := cr.Show(other, rel) // byte for byte
	if err != nil {
		f.t.Fatal(err)
	}
	write(f.clone, rel, string(b))
	git(f.t, f.clone, "add", "-A")
	tree := git(f.t, f.clone, "write-tree")
	rev := git(f.t, f.clone, "-c", "user.name="+as, "-c", "user.email="+as+"@yars.local", "commit-tree", tree, "-p", "HEAD", "-p", other, "-m", "merge")
	git(f.t, f.clone, "reset", "-q", "--soft", rev)
	return rev
}

// A merge is checked against the server's line for every file it leaves
// different from the server: taking an old server version of an approved
// finding as the "other side" does not bypass its lock.
func TestPolicyMergeOldVersionLocked(t *testing.T) {
	f := newFx(t)
	st := f.st
	v1 := git(t, f.repo().Dir, "rev-parse", "HEAD")
	st.UpdateSection("acme", "F-001-sqli", "Impact", "v2 impact", "", user("alice").GitAuthor())
	st.SetReviewers("acme", "F-001-sqli", []string{"bob"}, user("alice"))
	st.UpdateSeverity("acme", "F-001-sqli", "high", "", user("alice").GitAuthor())
	st.Transition("acme", "F-001-sqli", workflow.Submit, "", user("alice"))
	st.Transition("acme", "F-001-sqli", workflow.Clear, "", user("bob"))
	if err := st.Transition("acme", "F-001-sqli", workflow.Approve, "", user("dora")); err != nil {
		t.Fatal(err)
	}
	f.reclone()
	rev := f.mergeOf("alice", v1, fdir+"/finding.md")
	if ps := f.check("alice", rev); !has(ps, "complete") {
		t.Fatalf("approved finding rewritten through a merge: %v", ps)
	}
}

// A side branch that adds the finding afresh (from before it existed) and
// a merge that takes that version: the author change is still caught.
func TestPolicyMergeAuthorChange(t *testing.T) {
	f := newFx(t)
	root := git(t, f.repo().Dir, "rev-list", "--max-parents=0", "HEAD")
	f.reclone()
	as := []string{"-c", "user.name=pen2", "-c", "user.email=pen2@yars.local"}
	run := func(args ...string) string { return git(t, f.clone, append(slices.Clone(as), args...)...) }
	run("switch", "-qc", "side", root)
	newFinding("F-001-sqli", "id: F-001\ntitle: SQLi\nauthor: pen2\n")(f.clone)
	run("add", "-A")
	run("commit", "-qm", "side: my F-001")
	side := run("rev-parse", "HEAD")
	run("switch", "-q", "main")
	rev := f.mergeOf("pen2", side, fdir+"/finding.md")
	if ps := f.check("pen2", rev); !has(ps, "author cannot change") {
		t.Fatalf("author changed through a merge: %v", ps)
	}
}

// Attachments are held to the website's upload rules: images or text, not
// executable, plain names directly in attachments/, at most 10 MB; a big
// file a later commit deletes is still refused (history keeps it).
func TestPolicyAttachmentRules(t *testing.T) {
	f := newFx(t)
	cases := map[string]func(string){
		"only images and text files can be attached": func(d string) {
			write(d, fdir+"/attachments/poc.png", "\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
		},
		"cannot be executable": func(d string) {
			write(d, fdir+"/attachments/run.txt", "echo hi\n")
			os.Chmod(filepath.Join(d, fdir, "attachments", "run.txt"), 0o755)
		},
		"attachment names are":  func(d string) { write(d, fdir+"/attachments/sub/x.txt", "x") },
		"attachment names are ": func(d string) { write(d, fdir+"/attachments/a b.txt", "x") },
	}
	for want, edit := range cases {
		f.reclone()
		if ps := f.push("alice", edit); !has(ps, "commit "+short(t, f.clone, "HEAD")+" "+fdir+"/attachments/") || !has(ps, want) {
			t.Errorf("%s: %v", want, ps)
		}
	}
	f.reclone()
	write(f.clone, fdir+"/attachments/big.txt", strings.Repeat("a", 11<<20))
	git(t, f.clone, "add", "-A")
	git(t, f.clone, "-c", "user.name=alice", "-c", "user.email=alice@yars.local", "commit", "-qm", "big")
	big := short(t, f.clone, "HEAD")
	ps := f.push("alice", func(d string) { os.Remove(filepath.Join(d, fdir, "attachments", "big.txt")) })
	if !has(ps, "commit "+big+" "+fdir+"/attachments/big.txt: 11.0 MB; files over 10 MB are not accepted") {
		t.Fatalf("big file in history: %v", ps)
	}
}

// A file name with a control character (git allows a line break) is
// refused by name, with its commit, never as a server error.
func TestPolicyControlCharacterName(t *testing.T) {
	f := newFx(t)
	ps := f.push("alice", func(d string) { write(d, fdir+"/attachments/a\nb.txt", "x") })
	if !hasLine(ps, "commit "+short(t, f.clone, "HEAD")+" ", "control characters") || has(ps, "server") {
		t.Fatalf("newline in a name: %v", ps)
	}
}

// A long refusal lists the first problems and sums up the rest.
func TestPolicyProblemsCapped(t *testing.T) {
	f := newFx(t)
	ps := f.push("alice", func(d string) {
		for i := range 60 {
			write(d, "stray"+strconv.Itoa(i)+".txt", "x")
		}
	})
	if len(ps) != maxProblems+1 || !strings.HasPrefix(ps[maxProblems], "… and 10 more problems") {
		t.Fatalf("%d problems, last %q", len(ps), ps[len(ps)-1])
	}
}

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
	// removing one, as a pentester with porcelain commands
	f.reclone()
	if ps := f.pushAs("alice", "alice", func(d string) { git(t, d, "rm", "-q", "--cached", "engagements/acme") }); !has(ps, "engagements/acme: engagement pointers are managed by the server") {
		t.Fatalf("pointer removed by push: %v", ps)
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

// pushWith commits as git author name <email> and checks the push as u.
func (f *fx) pushWith(u, name, email string, edit func(dir string)) []string {
	f.t.Helper()
	edit(f.clone)
	git(f.t, f.clone, "add", "-A")
	git(f.t, f.clone, "-c", "user.name="+name, "-c", "user.email="+email, "commit", "-qm", "change", "--allow-empty")
	return f.check(u, git(f.t, f.clone, "rev-parse", "HEAD"))
}

// A commit counts as the pusher's by its author email alone: the account's
// email, whatever the name. The pusher's own username with another email is
// refused, directors included, with the commit and both emails named.
func TestPolicyAuthorEmail(t *testing.T) {
	f := newFx(t)
	edit := func(d string) { write(d, fdir+"/attachments/a.txt", "x") }
	ps := f.pushWith("alice", "alice", "a@a", edit)
	short := git(t, f.clone, "rev-parse", "--short=7", "HEAD")
	if !has(ps, "commit "+short+": ") || !has(ps, "a@a") || !has(ps, "alice@yars.local") {
		t.Fatalf("own name, other email: %v", ps)
	}
	f.reclone()
	if ps := f.pushWith("alice", "Alice Liddell", "alice@yars.local", edit); len(ps) != 0 {
		t.Fatalf("own email, other name refused: %v", ps)
	}
	f.reclone()
	if ps := f.pushWith("alice", "alice", "ALICE@yars.local", edit); len(ps) != 0 {
		t.Fatalf("email case refused: %v", ps)
	}
	f.reclone()
	if ps := f.pushWith("dora", "dora", "dora@elsewhere.example", edit); !has(ps, "dora@elsewhere.example") {
		t.Fatalf("director with another email accepted: %v", ps)
	}
	// letter case folds as the database compares (ASCII only): an account
	// email with the Kelvin sign is not kim's address
	f.reclone()
	f.c.Users = append(f.c.Users, config.User{Username: "mallory", Role: "pentester", Email: "Kim@corp.example"})
	f.st.DB().AddMembers("acme", "mallory")
	if ps := f.pushWith("mallory", "Kim", "kim@corp.example", edit); !has(ps, "kim@corp.example") {
		t.Fatalf("Kelvin-sign email matched kim's: %v", ps)
	}
}

// Accounts that shared an email before emails had to be unique can't tell
// whose a commit is: neither may push until an admin changes one.
func TestPolicySharedEmail(t *testing.T) {
	f := newFx(t)
	f.c.Users = append(slices.Clone(users), config.User{Username: "bob2", Role: "pentester", Email: "Alice@yars.local"})
	ps := f.push("alice", func(d string) { write(d, fdir+"/attachments/a.txt", "x") })
	if !has(ps, "bob2") || !has(ps, "alice@yars.local") || !has(ps, "Settings › Account") {
		t.Fatalf("shared email accepted: %v", ps)
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
