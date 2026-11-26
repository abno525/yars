package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/workflow"
)

// A content edit through YARS tells what changed (finding.updated).
func TestUpdatedEvent(t *testing.T) {
	s, _ := withEngagement(t)
	ref, err := s.CreateFinding(eng, "SQL injection", alice)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	s.OnEvent(rec.add)
	if err := s.UpdateSection(eng, ref.Dir, "Impact", "Full read.", "", uAlice); err != nil {
		t.Fatal(err)
	}
	e := rec.last(EventUpdated)
	if e.Actor != "alice" || e.Fid != "F-001" || e.Dir != ref.Dir || !slices.Equal(e.Changed, []string{"Impact"}) {
		t.Fatalf("updated %+v", e)
	}
	s.UpdateSeverity(eng, ref.Dir, "high", "", alice)
	if e := rec.last(EventUpdated); !slices.Equal(e.Changed, []string{"Severity"}) || e.Severity != "high" {
		t.Fatalf("severity %+v", e)
	}
	// nothing changed: no event
	n := len(rec.kinds())
	s.UpdateSection(eng, ref.Dir, "Impact", "Full read.", "", uAlice)
	if len(rec.kinds()) != n {
		t.Fatalf("event for a no-op: %v", rec.kinds())
	}
	if _, err := s.AddAttachment(eng, ref.Dir, "shot.png", []byte("png"), uAlice); err != nil {
		t.Fatal(err)
	}
	if e := rec.last(EventUpdated); !slices.Contains(e.Changed, "Attachments") {
		t.Fatalf("attachment %+v", e)
	}
}

// A push into the main repo runs under the main repo's lock (no settings
// commit can land between the hook's check and git's checkout), and a push
// that checked its tree out without moving the branch leaves HEAD's tree.
func TestReceivePushMainRepo(t *testing.T) {
	s, dir := withEngagement(t)
	s.ReceivePush("", uBob, func() {
		if s.mainMu.TryLock() {
			s.mainMu.Unlock()
			t.Error("main repo push served without the main repo lock")
		}
		os.WriteFile(filepath.Join(dir, "README.md"), []byte("rejected push"), 0o644)
		exec.Command("git", "-C", dir, "add", "README.md").Run()
	})
	if st, _ := exec.Command("git", "-C", dir, "status", "--porcelain", "--untracked-files=no", "--ignore-submodules=all").Output(); len(st) != 0 {
		t.Fatalf("main tree dirty after a push that did not land:\n%s", st)
	}
}

// The same for an engagement repo: a push that checked its tree out but
// never moved the branch leaves HEAD's tree behind.
func TestReceivePushRestoresEngagementTree(t *testing.T) {
	s, dir := withEngagement(t)
	ed := filepath.Join(dir, "engagements", eng)
	s.ReceivePush(eng, uBob, func() {
		os.WriteFile(filepath.Join(ed, "engagement.yaml"), []byte("rejected push"), 0o644)
		exec.Command("git", "-C", ed, "add", "engagement.yaml").Run()
	})
	if st, _ := exec.Command("git", "-C", ed, "status", "--porcelain", "--untracked-files=no").Output(); len(st) != 0 {
		t.Fatalf("engagement tree dirty after a push that did not land:\n%s", st)
	}
}

// A director's push to an approved finding keeps it approved once the push
// lands: the approval moves to the new content. A push that checked its tree
// out but never moved the branch leaves the approval where it was; a push by
// anyone else moves nothing (the finding is back in verification).
func TestReceivePushCarriesApproval(t *testing.T) {
	s, dir, fd := ready(t)
	for _, step := range []struct {
		a workflow.Action
		u config.User
	}{{workflow.Submit, uAlice}, {workflow.Clear, uBob}, {workflow.Approve, uDora}} {
		if err := s.Transition(eng, fd, step.a, "", step.u); err != nil {
			t.Fatal(err)
		}
	}
	ed := filepath.Join(dir, "engagements", eng)
	p := filepath.Join(ed, "findings", fd, "finding.md")
	edit := func(impact string) {
		b, _ := os.ReadFile(p)
		f, err := finding.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		f.SetSection("Impact", impact)
		os.WriteFile(p, f.Bytes(), 0o644)
	}
	approved := func() string {
		t.Helper()
		st, err := s.DB().State(eng, "F-001")
		if err != nil {
			t.Fatal(err)
		}
		return st.ApprovedHash
	}
	was := approved()
	s.ReceivePush(eng, uDora, func() { edit("never landed") })
	if got := approved(); got != was {
		t.Fatalf("a push that did not land moved the approval: %s, was %s", got, was)
	}
	if m := load(t, s, fd).F.Meta; m.Status != "complete" {
		t.Fatalf("after a push that did not land: %s", m.Status)
	}
	s.ReceivePush(eng, uDora, func() {
		edit("Director's polish.")
		git(t, ed, "commit", "-qam", "director's push")
	})
	if m := load(t, s, fd).F.Meta; m.Status != "complete" {
		t.Fatalf("a director's push sent the finding back to %s", m.Status)
	}
	raw, _ := os.ReadFile(p)
	if got := approved(); got != ApprovalHash(raw) {
		t.Fatalf("approval %s, content %s", got, ApprovalHash(raw))
	}
	s.ReceivePush(eng, uBob, func() {
		edit("A reviewer's words.")
		git(t, ed, "commit", "-qam", "reviewer's push")
	})
	if m := load(t, s, fd).F.Meta; m.Status != "verification" {
		t.Fatalf("a reviewer's push kept the approval: %s", m.Status)
	}
}

// A pushed attachment change drops the sign-offs of a finding in
// verification, as one through YARS does; a push that only renames the
// folder (the files move along, unchanged) keeps them.
func TestReceivePushAttachmentVoidsClearances(t *testing.T) {
	s, dir, fd := ready(t)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	ed := filepath.Join(dir, "engagements", eng)
	cleared := func() []string { t.Helper(); return load(t, s, "F-001-renamed").F.Meta.ClearedBy }
	s.ReceivePush(eng, uDora, func() {
		git(t, ed, "mv", "findings/"+fd, "findings/F-001-renamed")
		git(t, ed, "commit", "-qm", "rename")
	})
	if c := cleared(); !slices.Equal(c, []string{"bob"}) {
		t.Fatalf("a rename dropped the sign-offs: %v", c)
	}
	s.ReceivePush(eng, uBob, func() {
		os.MkdirAll(filepath.Join(ed, "findings", "F-001-renamed", "attachments"), 0o755)
		os.WriteFile(filepath.Join(ed, "findings", "F-001-renamed", "attachments", "req.txt"), []byte("GET / HTTP/1.1\n"), 0o644)
		git(t, ed, "add", "-A")
		git(t, ed, "commit", "-qm", "attach")
	})
	if c := cleared(); len(c) != 0 {
		t.Fatalf("a pushed attachment kept the sign-offs: %v", c)
	}
}

// A title edit rewrites only the title line: a file without severity or
// cvss keys (pushed over git) gets no empty ones added.
func TestTitleEditOnlyTitle(t *testing.T) {
	s, dir := withEngagement(t)
	ref, err := s.CreateFinding(eng, "SQL injection", alice)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "engagements", eng, "findings", ref.Dir, "finding.md")
	os.WriteFile(p, []byte("---\nid: F-001\ntitle: SQL injection\nauthor: alice\n---\n\n## Description\n\nx\n"), 0o644)
	ed := filepath.Join(dir, "engagements", eng)
	git(t, ed, "add", "-A")
	git(t, ed, "-c", "user.name=alice", "-c", "user.email=a@x", "commit", "-qm", "pushed")
	if err := s.UpdateTitle(eng, ref.Dir, "Blind SQL injection", uAlice); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if want := "---\nid: F-001\ntitle: Blind SQL injection\nauthor: alice\n---\n\n## Description\n\nx\n"; string(b) != want {
		t.Fatalf("file after a title edit:\n%s", b)
	}
}

// A director may push any .gitignore: YARS commits the paths it names even
// when the pattern ignores them (a new template, a new finding).
func TestCommitIgnoredPaths(t *testing.T) {
	s, dir := withEngagement(t)
	os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(".yars/\n*.md\nengagements/*\n"), 0o644)
	git(t, dir, "add", "-f", ".gitignore")
	git(t, dir, "-c", "user.name=dora", "-c", "user.email=d@x", "commit", "-qm", "ignore all")
	if err := s.SaveTemplate("sqli", alice, func(*finding.Finding) (*finding.Finding, error) { return s.NewTemplate("SQLi"), nil }); err != nil {
		t.Fatalf("template save under an ignoring .gitignore: %v", err)
	}
	ed := filepath.Join(dir, "engagements", eng)
	os.WriteFile(filepath.Join(ed, ".gitignore"), []byte("*.md\n"), 0o644)
	git(t, ed, "add", "-f", ".gitignore")
	git(t, ed, "-c", "user.name=dora", "-c", "user.email=d@x", "commit", "-qm", "ignore md")
	if _, err := s.CreateFinding(eng, "SQL injection", alice); err != nil {
		t.Fatalf("new finding under an ignoring .gitignore: %v", err)
	}
}

// Renaming a finding's folder is not a new finding: no finding.created; a
// rename that also edits it is finding.updated.
func TestReceivePushRename(t *testing.T) {
	s, dir := withEngagement(t)
	ref, err := s.CreateFinding(eng, "SQL injection", alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAttachment(eng, ref.Dir, "shot.png", []byte("png"), uAlice); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	s.OnEvent(rec.add)
	ed := filepath.Join(dir, "engagements", eng)
	s.ReceivePush(eng, uBob, func() {
		git(t, ed, "mv", "findings/"+ref.Dir, "findings/F-001-sqli-renamed")
		git(t, ed, "-c", "user.name=bob", "-c", "user.email=bob@x", "commit", "-qm", "rename")
	})
	if got := rec.kinds(); len(got) != 0 {
		t.Fatalf("events for a pure rename: %v", got)
	}
	s.ReceivePush(eng, uBob, func() {
		git(t, ed, "mv", "findings/F-001-sqli-renamed", "findings/F-001-sqli-login")
		p := filepath.Join(ed, "findings", "F-001-sqli-login", "finding.md")
		b, _ := os.ReadFile(p)
		f, _ := finding.Parse(b)
		f.SetSection("Impact", "Renamed and edited.")
		os.WriteFile(p, f.Bytes(), 0o644)
		git(t, ed, "add", "-A")
		git(t, ed, "-c", "user.name=bob", "-c", "user.email=bob@x", "commit", "-qm", "rename and edit")
	})
	if got := rec.kinds(); !slices.Equal(got, []string{EventUpdated}) {
		t.Fatalf("events for a rename with an edit: %v", got)
	}
	if u := rec.last(EventUpdated); u.Fid != "F-001" || u.Dir != "F-001-sqli-login" || !slices.Equal(u.Changed, []string{"Impact"}) {
		t.Fatalf("updated %+v", u)
	}
}

// A push (commits that land outside the store) emits the events the same
// changes made through YARS would: created for a new finding, updated with
// what changed for an edited one, attributed to the pusher.
func TestReceivePushEvents(t *testing.T) {
	s, dir := withEngagement(t)
	ref, err := s.CreateFinding(eng, "SQL injection", alice)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	s.OnEvent(rec.add)
	ed := filepath.Join(dir, "engagements", eng)
	s.ReceivePush(eng, uBob, func() {
		p := filepath.Join(ed, "findings", ref.Dir, "finding.md")
		b, _ := os.ReadFile(p)
		f, _ := finding.Parse(b)
		f.SetSection("Impact", "Pushed impact.")
		f.SetMeta("title", "SQL injection in login")
		os.WriteFile(p, f.Bytes(), 0o644)
		nf := finding.New("F-002", "XSS", "bob", s.Config().Sections)
		os.MkdirAll(filepath.Join(ed, "findings", "F-002-xss"), 0o755)
		os.WriteFile(filepath.Join(ed, "findings", "F-002-xss", "finding.md"), nf.Bytes(), 0o644)
		git(t, ed, "add", "-A")
		git(t, ed, "-c", "user.name=bob", "-c", "user.email=bob@x", "commit", "-qm", "push")
	})
	c := rec.last(EventCreated)
	if c.Fid != "F-002" || c.Dir != "F-002-xss" || c.Actor != "bob" || c.Title != "XSS" || c.Eng != eng {
		t.Fatalf("created %+v", c)
	}
	u := rec.last(EventUpdated)
	if u.Fid != "F-001" || u.Actor != "bob" || u.Title != "SQL injection in login" || !slices.Equal(u.Changed, []string{"Title", "Impact"}) {
		t.Fatalf("updated %+v", u)
	}
	if got := rec.kinds(); len(got) != 2 {
		t.Fatalf("kinds %v", got)
	}
	// the HEAD cache follows the push
	if h, _ := s.EngHead(eng); h != git(t, ed, "rev-parse", "HEAD") {
		t.Fatal("stale HEAD after push")
	}
	// a push that changes nothing (rejected) tells nothing
	s.ReceivePush(eng, uBob, func() {})
	if got := rec.kinds(); len(got) != 2 {
		t.Fatalf("kinds after empty push %v", got)
	}
}
