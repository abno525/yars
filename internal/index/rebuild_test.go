package index

import "testing"

// Rebuild reads every engagement again and remembers how long it took.
func TestRebuild(t *testing.T) {
	ix, _ := fixture(t)
	if _, err := ix.Rows(Query{}); err != nil {
		t.Fatal(err)
	}
	before := ix.rebuilds.Load()
	if ix.LastBuild() <= 0 {
		t.Fatal("first build not timed")
	}
	d, err := ix.Rebuild()
	if err != nil || d <= 0 {
		t.Fatal(d, err)
	}
	if n := ix.rebuilds.Load() - before; n != 2 {
		t.Fatalf("rebuild reloaded %d engagements, want 2", n)
	}
	if ix.LastBuild() != d {
		t.Fatalf("last build %v, rebuild %v", ix.LastBuild(), d)
	}
	rows, _ := ix.Rows(Query{})
	if len(rows) != 4 {
		t.Fatalf("rows after rebuild: %d", len(rows))
	}
	if n := ix.Findings(); n != 4 {
		t.Fatalf("findings %d", n)
	}
}
