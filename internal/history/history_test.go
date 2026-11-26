package history

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
)

var (
	alice = gitrepo.Author{Name: "alice", Email: "alice@x"}
	bob   = gitrepo.Author{Name: "bob", Email: "bob@x"}
)

func write(t *testing.T, r *gitrepo.Repo, rel, body string, a gitrepo.Author, msg string) {
	t.Helper()
	p := filepath.Join(r.Dir, rel)
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := r.Commit([]string{rel}, msg, a); err != nil {
		t.Fatal(err)
	}
}

const v1 = "---\nid: F-001\ntitle: SQLi\n---\n\n## Description\n\nOld text.\n\n## Impact\n\nBad.\n"
const v2 = "---\nid: F-001\ntitle: SQLi\nseverity: high\n---\n\n## Description\n\nOld text.\n\n## Impact\n\nVery bad.\nData loss.\n"

func TestVersionsFollowsAndCaches(t *testing.T) {
	r, err := gitrepo.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write(t, r, "findings/F-001-x/finding.md", v1, alice, "F-001: create")
	write(t, r, "other.txt", "x", alice, "unrelated")
	write(t, r, "findings/F-001-x/finding.md", v2, bob, "F-001: edit Impact")
	vs, err := Versions(r, "findings/F-001-x/finding.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 || vs[0].Author != "bob" || vs[0].Subject != "F-001: edit Impact" || vs[1].Author != "alice" || string(vs[0].Raw) != v2 || string(vs[1].Raw) != v1 {
		t.Fatalf("versions %+v", vs)
	}
	if vs[0].Time.IsZero() || len(vs[0].Hash) != 40 {
		t.Fatalf("time/hash %+v", vs[0])
	}
	// the cache answers again for the same head without git
	c := NewCache(8)
	head, _ := r.Head()
	before := gitrepo.Spawned()
	if _, err := c.Versions(r, "e/F-001", head, "findings/F-001-x/finding.md"); err != nil {
		t.Fatal(err)
	}
	mid := gitrepo.Spawned()
	if mid == before {
		t.Fatal("first read spawned no git")
	}
	if _, err := c.Versions(r, "e/F-001", head, "findings/F-001-x/finding.md"); err != nil {
		t.Fatal(err)
	}
	if gitrepo.Spawned() != mid {
		t.Fatal("cached read spawned git")
	}
}

func TestChangesPerSection(t *testing.T) {
	cs := Changes([]byte(v1), []byte(v2))
	if len(cs) != 2 {
		t.Fatalf("changes %+v", cs)
	}
	if cs[0].Name != FrontMatter || cs[0].Added != 1 || cs[0].Removed != 0 {
		t.Fatalf("front matter %+v", cs[0])
	}
	im := cs[1]
	if im.Name != "Impact" || im.Added != 2 || im.Removed != 1 || strings.TrimSpace(im.After) != "Very bad.\nData loss." {
		t.Fatalf("impact %+v", im)
	}
	var ops string
	for _, l := range im.Lines {
		ops += string(l.Op)
	}
	if ops != "-++" {
		t.Fatalf("ops %q %+v", ops, im.Lines)
	}
	// a first version: every section is new
	first := Changes(nil, []byte(v1))
	if len(first) != 3 || first[1].Name != "Description" || first[1].Added != 1 {
		t.Fatalf("first %+v", first)
	}
}

func TestDiffLines(t *testing.T) {
	ls := Diff("a\nb\nc", "a\nx\nc\nd")
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(string(l.Op) + l.Text + "|")
	}
	if b.String() != " a|-b|+x| c|+d|" {
		t.Fatalf("diff %q", b.String())
	}
	if ls[2].New != 2 || ls[1].Old != 2 || ls[1].New != 0 {
		t.Fatalf("numbers %+v", ls)
	}
}
