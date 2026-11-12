package store

import (
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/chat"
	"yars/internal/workflow"
)

// srcFixture: engagement 2026-11-acme with F-001 (complete, cleared by bob),
// F-002 (draft) and F-003 (draft).
func srcFixture(t *testing.T) (*Store, string) {
	t.Helper()
	s, dir, fd := ready(t)
	s.UpdateDetails(eng, fd, map[string]string{"Location": "/login"}, "", alice)
	s.UpdateSection(eng, fd, "Impact", "DB read", "", alice)
	s.Transition(eng, fd, workflow.Submit, "", uAlice)
	s.Transition(eng, fd, workflow.Clear, "", uBob)
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	s.PostChat(eng, fd, chatMsgText("old discussion"), uBob)
	s.CreateFinding(eng, "XSS", alice)
	s.CreateFinding(eng, "CSRF", alice)
	return s, dir
}

func chatMsgText(s string) chat.Message { return chat.Message{Text: s} }

// A withdrawn finding is not part of the report, so it can't be retested.
func TestRetestSkipsWithdrawn(t *testing.T) {
	s, _ := srcFixture(t)
	if err := s.Transition(eng, "F-002-xss", workflow.Withdraw, "duplicate", uAlice); err != nil {
		t.Fatal(err)
	}
	err := s.CreateRetest(Engagement{ID: "rt", Name: "RT"}, eng, []string{"F-001-sql-injection", "F-002-xss"}, "", uDora)
	if !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), "withdrawn") {
		t.Fatalf("err %v", err)
	}
}

func treeHash(t *testing.T, root string) map[string][32]byte {
	t.Helper()
	out := map[string][32]byte{}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir // git maintains its own files in the background
		}
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			out[p] = sha256.Sum256(b)
		}
		return nil
	})
	return out
}

func TestCreateRetest(t *testing.T) {
	s, dir := srcFixture(t)
	e := Engagement{ID: "2027-01-acme-retest", Name: "ACME retest"}
	if err := s.CreateRetest(e, eng, []string{"F-001-sql-injection", "F-003-csrf"}, "", uDora); err != nil {
		t.Fatal(err)
	}
	if got := logOf(t, filepath.Join(dir, "engagements", "2027-01-acme-retest"), "%an|%s"); got != "dora|engagement 2027-01-acme-retest: retest of 2026-11-acme (2 findings)" {
		t.Fatalf("commit %q", got)
	}
	ne, err := s.Engagement("2027-01-acme-retest")
	if err != nil || ne.Type != "retest" || ne.Source != eng {
		t.Fatalf("engagement %+v %v", ne, err)
	}
	refs, _ := s.ListFindings("2027-01-acme-retest")
	if len(refs) != 2 || refs[0].Dir != "F-001-sql-injection" {
		t.Fatalf("refs %+v", refs)
	}
	m := refs[0].F.Meta
	if m.Status != "draft" || m.Author != "alice" || len(m.Reviewers) != 0 || len(m.ClearedBy) != 0 || m.Returned != nil {
		t.Fatalf("meta %+v", m)
	}
	if m.Retest == nil || m.Retest.Source != eng+"/F-001-sql-injection" || m.Retest.Result != "" {
		t.Fatalf("retest %+v", m.Retest)
	}
	if m.Severity != "high" || m.Details["Location"] != "/login" || m.Title != "SQL injection" {
		t.Fatalf("content not copied %+v", m)
	}
	if b, _ := refs[0].F.Section("Impact"); strings.TrimSpace(b) != "DB read" {
		t.Fatalf("impact %q", b)
	}
	if msgs, _ := s.Chat("2027-01-acme-retest", "F-001-sql-injection"); len(msgs) != 0 {
		t.Fatal("chat copied")
	}
	// new findings in the retest continue numbering
	nf, err := s.CreateFinding("2027-01-acme-retest", "New issue", uAlice.GitAuthor())
	if err != nil || nf.F.Meta.ID != "F-004" || nf.F.Meta.Retest != nil {
		t.Fatalf("new finding %+v %v", nf.F.Meta, err)
	}
}

// A copy brings its finding's attachments, so the screenshots its text
// shows (attachments/…) are there in the retest too (backlog, M7).
func TestRetestCopiesAttachments(t *testing.T) {
	s, dir := srcFixture(t)
	png := []byte("\x89PNG\r\n\x1a\n" + strings.Repeat("x", 64))
	if _, err := s.AddAttachment(eng, "F-003-csrf", "shot.png", png, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAttachment(eng, "F-003-csrf", "notes.txt", []byte("steps"), alice); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRetest(Engagement{ID: "rt", Name: "RT"}, eng, []string{"F-001-sql-injection", "F-003-csrf"}, "", uDora); err != nil {
		t.Fatal(err)
	}
	as, err := s.Attachments("rt", "F-003-csrf")
	if err != nil || len(as) != 2 || as[0].Name != "notes.txt" || as[1].Name != "shot.png" {
		t.Fatalf("attachments %+v %v", as, err)
	}
	if b, err := s.ReadAttachment("rt", "F-003-csrf", "attachments/shot.png"); err != nil || string(b) != string(png) {
		t.Fatalf("shot.png %v", err)
	}
	if as, _ := s.Attachments("rt", "F-001-sql-injection"); len(as) != 0 {
		t.Fatalf("a finding without attachments got %+v", as)
	}
	if out, err := exec.Command("git", "-C", filepath.Join(dir, "engagements", "rt"), "status", "--porcelain").Output(); err != nil || len(out) != 0 {
		t.Fatalf("not committed: %v\n%s", err, out)
	}
}

// Copies keep the original author by default, so the tester can submit
// them; an explicit retester overrides it.
func TestCreateRetestAuthorship(t *testing.T) {
	s, _ := srcFixture(t)
	if err := s.CreateRetest(Engagement{ID: "rt1", Name: "RT"}, eng, []string{"F-001-sql-injection"}, "", uDora); err != nil {
		t.Fatal(err)
	}
	ref, _ := s.Finding("rt1", "F-001-sql-injection")
	if ref.F.Meta.Author != "alice" {
		t.Fatalf("author %q", ref.F.Meta.Author)
	}
	if err := s.CreateRetest(Engagement{ID: "rt2", Name: "RT"}, eng, []string{"F-001-sql-injection", "F-001-sql-injection"}, "carol", uDora); err != nil {
		t.Fatal(err)
	}
	ref, _ = s.Finding("rt2", "F-001-sql-injection")
	if ref.F.Meta.Author != "carol" {
		t.Fatalf("assigned author %q", ref.F.Meta.Author)
	}
}

func TestRetestLeavesSourceUntouched(t *testing.T) {
	s, dir := srcFixture(t)
	src := filepath.Join(dir, "engagements", eng)
	before := treeHash(t, src)
	s.CreateRetest(Engagement{ID: "rt", Name: "RT"}, eng, []string{"F-001-sql-injection", "F-002-xss", "F-003-csrf"}, "", uDora)
	after := treeHash(t, src)
	if len(before) != len(after) {
		t.Fatal("file count changed")
	}
	for p, h := range before {
		if after[p] != h {
			t.Fatalf("%s changed", p)
		}
	}
}

func TestRetestOfRetest(t *testing.T) {
	s, _ := srcFixture(t)
	s.CreateRetest(Engagement{ID: "rt1", Name: "RT1"}, eng, []string{"F-001-sql-injection"}, "", uDora)
	if err := s.SetRetestResult("rt1", "F-001-sql-injection", "not_fixed", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateRetest(Engagement{ID: "rt2", Name: "RT2"}, "rt1", []string{"F-001-sql-injection"}, "", uDora); err != nil {
		t.Fatal(err)
	}
	ref, _ := s.Finding("rt2", "F-001-sql-injection")
	if r := ref.F.Meta.Retest; r == nil || r.Source != "rt1/F-001-sql-injection" || r.Result != "" {
		t.Fatalf("retest %+v", r)
	}
}

func TestCreateRetestValidation(t *testing.T) {
	s, dir := srcFixture(t)
	before := last(t, dir, "%H")
	cases := []struct {
		e    Engagement
		src  string
		dirs []string
	}{
		{Engagement{ID: eng, Name: "dup"}, eng, []string{"F-001-sql-injection"}},
		{Engagement{ID: "../x", Name: "bad"}, eng, []string{"F-001-sql-injection"}},
		{Engagement{ID: "rt", Name: "empty"}, eng, nil},
		{Engagement{ID: "rt", Name: "missing"}, eng, []string{"F-009-nope"}},
		{Engagement{ID: "rt", Name: "nosrc"}, "nope", []string{"F-001-sql-injection"}},
		{Engagement{ID: "rt", Name: ""}, eng, []string{"F-001-sql-injection"}},
	}
	for _, c := range cases {
		if err := s.CreateRetest(c.e, c.src, c.dirs, "", uDora); err == nil {
			t.Errorf("%s accepted", c.e.Name)
		}
	}
	if last(t, dir, "%H") != before {
		t.Fatal("commit made")
	}
	if _, err := os.Stat(filepath.Join(dir, "engagements", "rt")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("partial engagement left behind")
	}
	if err := s.CreateRetest(Engagement{ID: "rt", Name: "RT"}, eng, []string{"F-001-sql-injection"}, "", uAlice); err == nil {
		t.Fatal("pentester created a retest")
	}
}

func TestSetRetestResult(t *testing.T) {
	s, dir := srcFixture(t)
	s.CreateRetest(Engagement{ID: "rt", Name: "RT"}, eng, []string{"F-001-sql-injection"}, "", uDora)
	before := last(t, dir, "%H")
	if err := s.SetRetestResult("rt", "F-001-sql-injection", "fixed", uDora); err != nil {
		t.Fatal(err)
	}
	if last(t, dir, "%H") != before {
		t.Fatal("retest result made a commit (it is workflow state)")
	}
	ref, _ := s.Finding("rt", "F-001-sql-injection")
	if ref.F.Meta.Retest.Result != "fixed" || ref.F.Meta.Retest.Source != eng+"/F-001-sql-injection" {
		t.Fatalf("retest %+v", ref.F.Meta.Retest)
	}
	if err := s.SetRetestResult("rt", "F-001-sql-injection", "maybe", uDora); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("err %v", err)
	}
	if err := s.SetRetestResult(eng, "F-002-xss", "fixed", uDora); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("non-retest err %v", err)
	}
}
