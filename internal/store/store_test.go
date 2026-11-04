package store

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/gitrepo"
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
	return New(r, config.Default()), dir
}

func last(t *testing.T, dir, format string) string {
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
	os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("x"), 0o644)
	git(t, dir, "add", "unrelated.txt")
	if err := s.UpdateSection("2026-11-acme", f.Dir, "Impact", "x", "", bob); err != nil {
		t.Fatal(err)
	}
	if files := git(t, dir, "show", "--name-only", "--format=", "HEAD"); strings.Contains(files, "unrelated") {
		t.Fatalf("commit swept in staged file: %s", files)
	}
}

func TestFailedCommitRollsBack(t *testing.T) {
	s, dir := withEngagement(t)
	f, _ := s.CreateFinding("2026-11-acme", "SQL injection", alice)
	lock := filepath.Join(dir, ".git", "index.lock")
	os.WriteFile(lock, nil, 0o644)
	if err := s.UpdateSection("2026-11-acme", f.Dir, "Impact", "x", "", bob); err == nil {
		t.Fatal("expected commit failure")
	}
	os.Remove(lock)
	if st := git(t, dir, "status", "--porcelain"); st != "" {
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
	s.beforeWrite = func() {
		os.WriteFile(filepath.Join(dir, "README.md"), []byte("pushed\n"), 0o644)
		git(t, dir, "add", "README.md")
		git(t, dir, "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-qm", "push")
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
