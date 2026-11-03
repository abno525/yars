package index

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

var alice = gitrepo.Author{Name: "alice", Email: "a@x"}

// setStatusSeverity rewrites a finding's front matter directly on disk and
// commits it, the way a local editor would.
func setMeta(t *testing.T, s *store.Store, eng, dir, status, sev string) {
	t.Helper()
	ref, err := s.Finding(eng, dir)
	if err != nil {
		t.Fatal(err)
	}
	ref.F.Meta.Status, ref.F.Meta.Severity = status, sev
	rel := filepath.Join("engagements", eng, "findings", dir, "finding.md")
	if err := os.WriteFile(filepath.Join(s.Repo().Dir, rel), ref.F.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Repo().Commit([]string{rel}, "meta", alice); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) (*Index, *store.Store) {
	t.Helper()
	r, err := gitrepo.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := store.New(r, config.Default())
	for _, e := range []string{"acme", "other"} {
		if err := s.CreateEngagement(store.Engagement{ID: e, Name: e}, alice); err != nil {
			t.Fatal(err)
		}
	}
	data := []struct{ title, status, sev string }{
		{"A", "reported", "low"},
		{"B", "draft", "critical"},
		{"C", "verification", "medium"},
	}
	for _, d := range data {
		f, err := s.CreateFinding("acme", d.title, alice)
		if err != nil {
			t.Fatal(err)
		}
		setMeta(t, s, "acme", f.Dir, d.status, d.sev)
	}
	if _, err := s.CreateFinding("other", "Z", alice); err != nil {
		t.Fatal(err)
	}
	return New(s, r), s
}

func titles(rows []Row) string {
	var t []string
	for _, r := range rows {
		t = append(t, r.Title)
	}
	return strings.Join(t, ",")
}

func TestFilterByEngagementAndStatus(t *testing.T) {
	ix, _ := fixture(t)
	rows, err := ix.Rows(Query{EngID: "acme"})
	if err != nil || titles(rows) != "A,B,C" {
		t.Fatalf("got %q %v", titles(rows), err)
	}
	rows, _ = ix.Rows(Query{EngID: "acme", Status: "draft"})
	if titles(rows) != "B" {
		t.Fatalf("got %q", titles(rows))
	}
}

func TestSortStatusWorkflowOrder(t *testing.T) {
	ix, _ := fixture(t)
	rows, _ := ix.Rows(Query{EngID: "acme", Sort: "status"})
	if titles(rows) != "B,C,A" {
		t.Fatalf("got %q", titles(rows))
	}
	rows, _ = ix.Rows(Query{EngID: "acme", Sort: "status", Desc: true})
	if titles(rows) != "A,C,B" {
		t.Fatalf("desc got %q", titles(rows))
	}
}

func TestSortIDDesc(t *testing.T) {
	ix, _ := fixture(t)
	rows, _ := ix.Rows(Query{EngID: "acme", Sort: "id", Desc: true})
	if titles(rows) != "C,B,A" {
		t.Fatalf("got %q", titles(rows))
	}
}

func TestSortSeverityOrder(t *testing.T) {
	ix, _ := fixture(t)
	rows, _ := ix.Rows(Query{EngID: "acme", Sort: "severity"})
	if titles(rows) != "B,C,A" {
		t.Fatalf("got %q", titles(rows))
	}
}

func TestExternalCommitVisible(t *testing.T) {
	ix, s := fixture(t)
	if _, err := ix.Rows(Query{EngID: "acme"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.Repo().Dir, "engagements", "acme", "findings", "F-009-ext")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "finding.md"), []byte("---\nid: F-009\ntitle: Ext\nstatus: draft\n---\n"), 0o644)
	for _, args := range [][]string{{"add", "-A"}, {"-c", "user.name=x", "-c", "user.email=x@x", "commit", "-qm", "ext"}} {
		if out, err := exec.Command("git", append([]string{"-C", s.Repo().Dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("%v %s", err, out)
		}
	}
	rows, _ := ix.Rows(Query{EngID: "acme"})
	if titles(rows) != "A,B,C,Ext" {
		t.Fatalf("got %q", titles(rows))
	}
}
