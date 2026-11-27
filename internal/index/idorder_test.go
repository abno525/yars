package index

import (
	"os"
	"path/filepath"
	"testing"
)

// The lists sort by the finding's number: F-999 before F-1000, in the
// default order and where another sort ties.
func TestRowsSortByNumber(t *testing.T) {
	ix, s := fixture(t)
	er, err := s.EngRepo("other")
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, n := range []string{"F-1000-b", "F-999-a", "F-7-c"} {
		rel := filepath.Join("findings", n, "finding.md")
		if err := os.MkdirAll(filepath.Join(er.Dir, "findings", n), 0o700); err != nil {
			t.Fatal(err)
		}
		// one severity and one author for all: every other sort ties
		if err := os.WriteFile(filepath.Join(er.Dir, rel), []byte("---\nid: "+n[:len(n)-2]+"\ntitle: "+n+"\nseverity: low\nauthor: alice\n---\n\n## Description\n\nx\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		rels = append(rels, rel)
	}
	if err := er.Commit(rels, "pushed", alice); err != nil {
		t.Fatal(err)
	}
	s.Invalidate("other")
	const want = "Z,F-7-c,F-999-a,F-1000-b" // Z is F-001
	for _, q := range []Query{{EngID: "other"}, {EngID: "other", Sort: "author"}, {EngID: "other", Sort: "author", Desc: true}} {
		rows, err := ix.Rows(q)
		if err != nil {
			t.Fatal(err)
		}
		if got := titles(rows); got != want {
			t.Errorf("sort %q desc %v: %s, want %s", q.Sort, q.Desc, got, want)
		}
	}
	rows, _ := ix.Rows(Query{EngID: "other", Desc: true})
	if got := titles(rows); got != "F-1000-b,F-999-a,F-7-c,Z" {
		t.Errorf("default sort, descending: %s", got)
	}
}
