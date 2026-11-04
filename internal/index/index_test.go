package index

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/chat"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

var alice = gitrepo.Author{Name: "alice", Email: "a@x"}

// setMeta rewrites a finding's severity directly on disk and commits it (the
// way a local editor would) and sets its status in the database.
func setMeta(t *testing.T, s *store.Store, eng, dir, status, sev string) {
	t.Helper()
	ref, err := s.Finding(eng, dir)
	if err != nil {
		t.Fatal(err)
	}
	ref.F.Meta.Severity = sev
	rel := filepath.Join("engagements", eng, "findings", dir, "finding.md")
	if err := os.WriteFile(filepath.Join(s.Repo().Dir, rel), ref.F.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Repo().Commit([]string{rel}, "meta", alice); err != nil {
		t.Fatal(err)
	}
	setStatus(t, s, eng, ref.F.Meta.ID, status)
}

func setStatus(t *testing.T, s *store.Store, eng, fid, status string) {
	t.Helper()
	if err := s.DB().Tx(func(tx *db.Tx) error { return tx.PutState(eng, fid, db.State{Status: status}) }); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) (*Index, *store.Store) {
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
	s := store.New(r, config.Default(), d)
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

// setCVSS writes cvss + severity directly (no derivation), like a local edit.
func setCVSS(t *testing.T, s *store.Store, eng, dir, vec, sev string) {
	t.Helper()
	ref, err := s.Finding(eng, dir)
	if err != nil {
		t.Fatal(err)
	}
	ref.F.Meta.CVSS, ref.F.Meta.Severity = vec, sev
	rel := filepath.Join("engagements", eng, "findings", dir, "finding.md")
	os.WriteFile(filepath.Join(s.Repo().Dir, rel), ref.F.Bytes(), 0o644)
	if err := s.Repo().Commit([]string{rel}, "cvss", alice); err != nil {
		t.Fatal(err)
	}
}

func byTitle(t *testing.T, rows []Row, title string) Row {
	for _, r := range rows {
		if r.Title == title {
			return r
		}
	}
	t.Fatalf("no row %s", title)
	return Row{}
}

func TestRowsDeriveSeverity(t *testing.T) {
	ix, s := fixture(t)
	setCVSS(t, s, "acme", "F-001-a", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "low")
	rows, _ := ix.Rows(Query{EngID: "acme"})
	if r := byTitle(t, rows, "A"); r.Severity != "critical" || r.Score != "9.8" {
		t.Fatalf("row %+v", r)
	}
	rows, _ = ix.Rows(Query{EngID: "acme", Severity: "critical"})
	if titles(rows) != "A,B" {
		t.Fatalf("filter got %q", titles(rows))
	}
}

func TestRowsForeignCVSS(t *testing.T) {
	ix, s := fixture(t)
	setCVSS(t, s, "acme", "F-001-a", "8.1", "medium")
	rows, _ := ix.Rows(Query{EngID: "acme"})
	if r := byTitle(t, rows, "A"); r.Severity != "medium" || r.Score != "" {
		t.Fatalf("row %+v", r)
	}
}

func TestSortByCVSS(t *testing.T) {
	ix, s := fixture(t)
	setCVSS(t, s, "acme", "F-001-a", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "")
	setCVSS(t, s, "acme", "F-003-c", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N", "")
	rows, _ := ix.Rows(Query{EngID: "acme", Sort: "cvss"})
	if titles(rows) != "B,C,A" {
		t.Fatalf("asc got %q", titles(rows))
	}
	rows, _ = ix.Rows(Query{EngID: "acme", Sort: "cvss", Desc: true})
	if titles(rows) != "A,C,B" {
		t.Fatalf("desc got %q", titles(rows))
	}
}

func TestRowsOpenThreads(t *testing.T) {
	ix, s := fixture(t)
	u := config.User{Username: "bob", Role: "reviewer"}
	t1, _ := s.PostChat("acme", "F-002-b", chat.Message{Text: "one"}, u)
	s.PostChat("acme", "F-002-b", chat.Message{Text: "two"}, u)
	s.PostChat("acme", "F-002-b", chat.Message{Resolves: t1.ID}, u)
	rows, _ := ix.Rows(Query{EngID: "acme", Sort: "chat", Desc: true})
	if rows[0].Title != "B" || rows[0].OpenThreads != 1 || rows[1].OpenThreads != 0 {
		t.Fatalf("rows %+v", rows)
	}
}

// A workflow change is a database write with no commit; the index must
// still see it.
func TestStateChangeVisibleWithoutCommit(t *testing.T) {
	ix, s := fixture(t)
	if rows, _ := ix.Rows(Query{EngID: "acme", Status: "complete"}); len(rows) != 0 {
		t.Fatalf("rows %+v", rows)
	}
	setStatus(t, s, "acme", "F-002", "complete")
	if rows, _ := ix.Rows(Query{EngID: "acme", Status: "complete"}); titles(rows) != "B" {
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
