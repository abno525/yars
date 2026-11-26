package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/gitrepo"
)

var alice = gitrepo.Author{Name: "alice", Email: "alice@yars.local"}
var bob = gitrepo.Author{Name: "bob", Email: "bob@yars.local"}

func newStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	r, err := gitrepo.Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return New(r, config.Default(), d), dir
}

// last formats the newest commit of the repo at dir. For the data dir it
// looks at the test engagement's own repo (where finding commits go) when
// that exists; pass an engagement dir or mainLast for others.
func last(t *testing.T, dir, format string) string {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, "engagements", eng, ".git")); err == nil {
		dir = filepath.Join(dir, "engagements", eng)
	}
	return logOf(t, dir, format)
}

// mainLast formats the newest commit of the main repo.
func mainLast(t *testing.T, dir, format string) string { t.Helper(); return logOf(t, dir, format) }

func logOf(t *testing.T, dir, format string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", dir, "log", "-1", "--format="+format).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func withEngagement(t *testing.T) (*Store, string) {
	s, dir := newStore(t)
	if err := s.CreateEngagement(Engagement{ID: "2026-11-acme", Name: "ACME web", Client: "ACME", Type: "pentest"}, alice); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func TestCreateEngagementAndList(t *testing.T) {
	s, dir := withEngagement(t)
	es, err := s.ListEngagements()
	if err != nil || len(es) != 1 || es[0].ID != "2026-11-acme" || es[0].Name != "ACME web" {
		t.Fatalf("got %+v %v", es, err)
	}
	if got := last(t, dir, "%s"); got != "engagement 2026-11-acme: create" {
		t.Fatalf("subject %q", got)
	}
	if err := s.CreateEngagement(Engagement{ID: "2026-11-acme"}, alice); err == nil {
		t.Fatal("duplicate engagement allowed")
	}
}

// Each engagement is its own repository; the main repo records it as a
// submodule (gitlink + .gitmodules entry) and gets no finding commits.
func TestEngagementIsOwnRepo(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding(eng, "SQLi", alice)
	s.UpdateSection(eng, f.Dir, "Impact", "DB read", "", bob)
	engDir := filepath.Join(dir, "engagements", eng)
	if got := git(t, engDir, "log", "--format=%s"); got != "F-001: edit Impact\nF-001: create\nengagement "+eng+": create" {
		t.Fatalf("engagement history:\n%s", got)
	}
	if got := git(t, dir, "log", "--format=%s"); strings.Contains(got, "F-001") {
		t.Fatalf("finding commits in the main repo:\n%s", got)
	}
	if got := git(t, dir, "ls-tree", "HEAD", "engagements/"+eng); !strings.HasPrefix(got, "160000 commit ") {
		t.Fatalf("no gitlink: %q", got)
	}
	gm, _ := os.ReadFile(filepath.Join(dir, ".gitmodules"))
	if !strings.Contains(string(gm), `[submodule "engagements/`+eng+`"]`) || !strings.Contains(string(gm), "url = ../e/"+eng) || !strings.Contains(string(gm), "branch = main") {
		t.Fatalf(".gitmodules:\n%s", gm)
	}
}

// If adding the engagement to the main repo fails, the main repo is left
// exactly as it was (a dirty main repo would refuse every settings push).
func TestCreateEngagementRollsBackMain(t *testing.T) {
	s, dir := withEngagement(t)
	before, _ := os.ReadFile(filepath.Join(dir, ".gitmodules"))
	lock := filepath.Join(dir, ".git", "index.lock")
	os.WriteFile(lock, nil, 0o644)
	if err := s.CreateEngagement(Engagement{ID: "beta", Name: "B"}, alice); err == nil {
		t.Fatal("expected failure")
	}
	os.Remove(lock)
	if after, _ := os.ReadFile(filepath.Join(dir, ".gitmodules")); string(after) != string(before) {
		t.Fatalf(".gitmodules left changed:\n%s", after)
	}
	if st := git(t, dir, "status", "--porcelain"); st != "" {
		t.Fatalf("main repo dirty:\n%s", st)
	}
	if _, err := os.Stat(filepath.Join(dir, "engagements", "beta")); err == nil {
		t.Fatal("half-created engagement left behind")
	}
	if err := s.CreateEngagement(Engagement{ID: "beta", Name: "B"}, alice); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

// The main repo's pointers catch up in one commit; a second sync is a no-op.
func TestSyncPointers(t *testing.T) {
	s, dir := withEngagement(t)
	s.CreateFinding(eng, "SQLi", alice)
	if err := s.SyncPointers(); err != nil {
		t.Fatal(err)
	}
	head := git(t, dir, "rev-parse", "HEAD")
	if got := git(t, dir, "log", "-1", "--format=%an|%s"); got != "yars|engagements: update "+eng {
		t.Fatalf("sync commit %q", got)
	}
	if link := git(t, dir, "rev-parse", "HEAD:engagements/"+eng); link != git(t, filepath.Join(dir, "engagements", eng), "rev-parse", "HEAD") {
		t.Fatal("pointer not at the engagement's HEAD")
	}
	if err := s.SyncPointers(); err != nil {
		t.Fatal(err)
	}
	if git(t, dir, "rev-parse", "HEAD") != head {
		t.Fatal("second sync made a commit")
	}
}

func TestCreateFindingNumbering(t *testing.T) {
	s, dir := withEngagement(t)
	f1, err := s.CreateFinding("2026-11-acme", "SQL injection in login", alice)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := s.CreateFinding("2026-11-acme", "Reflected XSS", alice)
	if err != nil {
		t.Fatal(err)
	}
	if f1.Dir != "F-001-sql-injection-in-login" || f1.F.Meta.ID != "F-001" {
		t.Fatalf("f1 %s %s", f1.Dir, f1.F.Meta.ID)
	}
	if f2.Dir != "F-002-reflected-xss" || f2.F.Meta.ID != "F-002" {
		t.Fatalf("f2 %s %s", f2.Dir, f2.F.Meta.ID)
	}
	if f2.F.Meta.Author != "alice" || f2.F.Meta.Status != "draft" {
		t.Fatalf("meta %+v", f2.F.Meta)
	}
	if got := last(t, dir, "%an|%s"); got != "alice|F-002: create" {
		t.Fatalf("commit %q", got)
	}
	got, err := s.ListFindings("2026-11-acme")
	if err != nil || len(got) != 2 {
		t.Fatalf("list %v %v", got, err)
	}
}

// Findings are addressed in URLs by number only ("002"); the full directory
// name still works.
func TestFindingByNumber(t *testing.T) {
	s, _ := withEngagement(t)
	s.CreateFinding("2026-11-acme", "SQL injection in login", alice)
	s.CreateFinding("2026-11-acme", "Reflected XSS", alice)
	for _, key := range []string{"002", "2", "F-002-reflected-xss"} {
		ref, err := s.Finding("2026-11-acme", key)
		if err != nil || ref.Dir != "F-002-reflected-xss" {
			t.Errorf("%s: %v %q", key, err, ref.Dir)
		}
	}
	for _, key := range []string{"003", "0", "x2"} {
		if _, err := s.Finding("2026-11-acme", key); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v", key, err)
		}
	}
	if ShortID("F-002-reflected-xss") != "002" || ShortID("F-010") != "010" || ShortID("custom-dir") != "custom-dir" {
		t.Error("ShortID")
	}
}

func TestCreateFindingUnknownEngagement(t *testing.T) {
	s, dir := newStore(t)
	if _, err := s.CreateFinding("nope", "x", alice); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "engagements", "nope")); !os.IsNotExist(err) {
		t.Fatal("files written for unknown engagement")
	}
}

func TestUpdateSection(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding("2026-11-acme", "SQL injection", alice)
	if err := s.UpdateSection("2026-11-acme", f.Dir, "Impact", "Full DB read.", "", bob); err != nil {
		t.Fatal(err)
	}
	re, err := s.Finding("2026-11-acme", f.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := re.F.Section("Impact"); strings.TrimSpace(b) != "Full DB read." {
		t.Fatalf("Impact %q", b)
	}
	if b, _ := re.F.Section("Description"); strings.TrimSpace(b) != "" {
		t.Fatalf("Description changed %q", b)
	}
	if got := last(t, dir, "%an|%s"); got != "bob|F-001: edit Impact" {
		t.Fatalf("commit %q", got)
	}
}

// Chat posts and workflow changes read findings without the engagement's
// lock, so an edit must replace the file in one step (write a temporary
// file, rename it) rather than truncate and rewrite it in place: a reader
// never sees a half-written finding (and an approval is never bound to the
// hash of one).
func TestEditReplacesFileAtomically(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding("2026-11-acme", "SQL injection", alice)
	p := filepath.Join(dir, "engagements", "2026-11-acme", "findings", f.Dir, "finding.md")
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSection("2026-11-acme", f.Dir, "Impact", "Full DB read.", "", bob); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("finding.md was rewritten in place")
	}
	if after.Mode().Perm() != 0o600 { // the service user's alone (pre1 2.23)
		t.Fatalf("mode %v", after.Mode())
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range ents {
		if e.Name() != "finding.md" {
			t.Fatalf("left behind %s", e.Name())
		}
	}
}

func TestInvalidIDs(t *testing.T) {
	s, _ := withEngagement(t)
	if _, err := s.Finding("..", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := s.Finding("2026-11-acme", "../x"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := s.Engagement("a/b"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.UpdateSection("2026-11-acme", "..", "Impact", "x", "", bob); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=x", "-c", "user.email=x@x"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestUpdateSectionRejectsBadBody(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding("2026-11-acme", "SQL injection", alice)
	head := last(t, dir, "%H")
	for _, body := range []string{"x\n## Impact\ny", "```\nunclosed"} {
		if err := s.UpdateSection("2026-11-acme", f.Dir, "Location", body, "", bob); !errors.Is(err, ErrInvalidBody) {
			t.Fatalf("%q: err %v", body, err)
		}
	}
	if last(t, dir, "%H") != head {
		t.Fatal("invalid body committed")
	}
}

func TestUpdateSectionConflict(t *testing.T) {
	s, _ := withEngagement(t)
	f, _ := s.CreateFinding("2026-11-acme", "SQL injection", alice)
	body, _ := f.F.Section("Impact")
	base := BodyHash(body)
	if err := s.UpdateSection("2026-11-acme", f.Dir, "Impact", "alice text", base, alice); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSection("2026-11-acme", f.Dir, "Impact", "bob text", base, bob); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save err %v", err)
	}
	re, _ := s.Finding("2026-11-acme", f.Dir)
	if b, _ := re.F.Section("Impact"); strings.TrimSpace(b) != "alice text" {
		t.Fatalf("Impact overwritten: %q", b)
	}
}

func TestSymlinkEscapeBlocked(t *testing.T) {
	s, dir := withEngagement(t)
	outside := filepath.Join(t.TempDir(), "secret.md")
	content := "---\nid: F-009\ntitle: secret\n---\n## Impact\nsecret\n"
	os.WriteFile(outside, []byte(content), 0o644)
	fd := filepath.Join(dir, "engagements", "2026-11-acme", "findings", "F-009-x")
	os.MkdirAll(fd, 0o755)
	if err := os.Symlink(outside, filepath.Join(fd, "finding.md")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Finding("2026-11-acme", "F-009-x"); err == nil {
		t.Fatal("read through symlink outside repo")
	}
	s.UpdateSection("2026-11-acme", "F-009-x", "Impact", "pwned", "", bob)
	if b, _ := os.ReadFile(outside); string(b) != content {
		t.Fatal("wrote through symlink outside repo")
	}
}

func TestCommitOnlyOwnPaths(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding("2026-11-acme", "SQL injection", alice)
	ed := filepath.Join(dir, "engagements", eng)
	os.WriteFile(filepath.Join(ed, "unrelated.txt"), []byte("x"), 0o644)
	git(t, ed, "add", "unrelated.txt")
	if err := s.UpdateSection("2026-11-acme", f.Dir, "Impact", "x", "", bob); err != nil {
		t.Fatal(err)
	}
	if files := git(t, ed, "show", "--name-only", "--format=", "HEAD"); strings.Contains(files, "unrelated") {
		t.Fatalf("commit swept in staged file: %s", files)
	}
}

func TestFailedCommitRollsBack(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding("2026-11-acme", "SQL injection", alice)
	ed := filepath.Join(dir, "engagements", eng)
	lock := filepath.Join(ed, ".git", "index.lock")
	os.WriteFile(lock, nil, 0o644)
	if err := s.UpdateSection("2026-11-acme", f.Dir, "Impact", "x", "", bob); err == nil {
		t.Fatal("expected commit failure")
	}
	os.Remove(lock)
	if st := git(t, ed, "status", "--porcelain"); st != "" {
		t.Fatalf("dirty tree after failed commit: %s", st)
	}
}

func TestDotIDRejected(t *testing.T) {
	s, dir := newStore(t)
	for _, id := range []string{".git", ".hidden"} {
		if err := s.CreateEngagement(Engagement{ID: id, Name: "x"}, alice); err == nil {
			t.Fatalf("%s accepted", id)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "engagements", ".git")); !os.IsNotExist(err) {
		t.Fatal("dot dir created")
	}
}

// A push (or any external commit) landing while a web edit is being
// prepared must not be overwritten by that edit.
func TestWriteAbortsIfRepoMoved(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding("2026-11-acme", "SQL injection", alice)
	ed := filepath.Join(dir, "engagements", eng)
	s.beforeWrite = func() {
		os.WriteFile(filepath.Join(ed, "README.md"), []byte("pushed\n"), 0o644)
		git(t, ed, "add", "README.md")
		git(t, ed, "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-qm", "push")
	}
	err := s.UpdateSection("2026-11-acme", f.Dir, "Impact", "web text", "", bob)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err %v", err)
	}
	s.beforeWrite = nil
	ref, _ := s.Finding("2026-11-acme", f.Dir)
	if b, _ := ref.F.Section("Impact"); strings.Contains(b, "web text") {
		t.Fatal("stale write landed")
	}
}

func TestUpdateTitle(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding("2026-11-acme", "SQL injection", alice)
	if err := s.UpdateTitle("2026-11-acme", f.Dir, "  SQL injection in login  ", bob); err != nil {
		t.Fatal(err)
	}
	ref, _ := s.Finding("2026-11-acme", f.Dir)
	if ref.F.Meta.Title != "SQL injection in login" || last(t, dir, "%s") != "F-001: edit title" {
		t.Fatalf("title %q", ref.F.Meta.Title)
	}
	for _, bad := range []string{"", "  ", "two\nlines", strings.Repeat("x", 201)} {
		if err := s.UpdateTitle("2026-11-acme", f.Dir, bad, bob); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestReadAttachment(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding("2026-11-acme", "SQL injection", alice)
	att := filepath.Join(dir, "engagements", "2026-11-acme", "findings", f.Dir, "attachments")
	os.MkdirAll(att, 0o755)
	os.WriteFile(filepath.Join(att, "a.png"), []byte("img"), 0o644)
	if b, err := s.ReadAttachment("2026-11-acme", f.Dir, "attachments/a.png"); err != nil || string(b) != "img" {
		t.Fatalf("%q %v", b, err)
	}
	for _, bad := range []string{"../finding.md", "attachments/../finding.md", "finding.md", "attachments/.hidden", "attachments/sub/a.png"} {
		if _, err := s.ReadAttachment("2026-11-acme", f.Dir, bad); err == nil {
			t.Errorf("%s readable", bad)
		}
	}
}

func TestUpdateSectionUnchangedIsNoop(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding("2026-11-acme", "SQL injection", alice)
	if err := s.UpdateSection("2026-11-acme", f.Dir, "Impact", "x", "", bob); err != nil {
		t.Fatal(err)
	}
	head := last(t, dir, "%H")
	if err := s.UpdateSection("2026-11-acme", f.Dir, "Impact", "x", "", bob); err != nil {
		t.Fatalf("unchanged save errored: %v", err)
	}
	if last(t, dir, "%H") != head {
		t.Fatal("unchanged save created a commit")
	}
}

var (
	m17Dir = config.User{Username: "dora", Role: "director"}
	m17Pen = config.User{Username: "alice", Role: "pentester"}
)

func newTemplate(t *testing.T, s *Store, slug, title string) {
	t.Helper()
	err := s.SaveTemplate(slug, alice, func(cur *finding.Finding) (*finding.Finding, error) {
		if cur != nil {
			t.Fatalf("template %s exists", slug)
		}
		f := s.NewTemplate(title)
		f.SetSection("Description", "The server does not send HSTS.")
		if err := f.SetMeta("severity", "low"); err != nil {
			return nil, err
		}
		return f, f.SetMeta("cvss", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N")
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Configurations apply one at a time, subscribers included: one applied
// while another is still being handed to the subscribers waits, so the
// store and every subscriber end with the last one (D12).
func TestSetConfigInOrder(t *testing.T) {
	s, _ := withEngagement(t)
	var mu sync.Mutex
	last := ""
	gate, entered := make(chan struct{}), make(chan struct{}, 4)
	s.OnConfig(func(c config.Config) {
		entered <- struct{}{}
		if c.Sections[0] == "X" {
			<-gate
		}
		mu.Lock()
		last = c.Sections[0]
		mu.Unlock()
	})
	x, y := s.Config(), s.Config()
	x.Sections, y.Sections = []string{"X"}, []string{"Y"}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.SetConfig(x) }()
	<-entered
	done := make(chan struct{})
	go func() { defer wg.Done(); s.SetConfig(y); close(done) }()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
	}
	close(gate)
	wg.Wait()
	if last != "Y" || s.Config().Sections[0] != "Y" {
		t.Fatalf("subscriber has %s, store %v", last, s.Config().Sections)
	}
}

func TestSetConfigApplies(t *testing.T) {
	s, _ := withEngagement(t)
	c := s.Config()
	c.Sections = []string{"Summary", "Fix"}
	s.SetConfig(c)
	ref, err := s.CreateFinding(eng, "x", alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(ref.F.Sections) != 2 || ref.F.Sections[0].Name != "Summary" {
		t.Fatalf("sections %+v", ref.F.Sections)
	}
}
