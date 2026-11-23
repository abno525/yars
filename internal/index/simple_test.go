package index

import (
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/store"
)

// In the simple workflow the bars and legends count draft, complete,
// reported and withdrawn, in that order: no verification, no signed off. A
// stored verification counts as draft.
func TestSimpleSummaryStatuses(t *testing.T) {
	r, err := gitrepo.Init(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.Open(filepath.Join(t.TempDir(), "yars.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	cfg := config.Default()
	cfg.Workflow = config.WorkflowSimple
	s := store.New(r, cfg, d)
	if err := s.CreateEngagement(store.Engagement{ID: "acme", Name: "acme"}, alice); err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct{ title, status, sev string }{
		{"A", "draft", "low"}, {"B", "verification", "high"}, {"C", "complete", "medium"},
		{"D", "reported", "critical"}, {"E", "withdrawn", "info"},
	} {
		f, err := s.CreateFinding("acme", x.title, alice)
		if err != nil {
			t.Fatal(err)
		}
		setMeta(t, s, "acme", f.Dir, x.status, x.sev)
	}
	ix := New(s, r)
	sum, err := ix.Summary("acme")
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, c := range sum.Statuses {
		keys = append(keys, c.Key)
	}
	if strings.Join(keys, ",") != "draft,complete,reported,withdrawn" {
		t.Fatalf("keys %v", keys)
	}
	if sum.Total != 4 || sum.Done != 2 || sum.Progress != 50 || sum.Statuses[0].N != 2 || sum.Statuses[0].Pct != 50 || sum.Statuses[3].N != 1 {
		t.Fatalf("summary %+v", sum)
	}
	if sum.ByShown["verification"] != 0 || sum.ByStatus["verification"] != 0 {
		t.Fatalf("verification counted: %v %v", sum.ByShown, sum.ByStatus)
	}
	rows, err := ix.Rows(Query{EngID: "acme", Sort: "status"})
	if err != nil {
		t.Fatal(err)
	}
	if titles(rows) != "A,B,C,D" || rows[1].Status != "draft" || rows[1].Shown != "draft" {
		t.Fatalf("rows %s, B %s/%s", titles(rows), rows[1].Status, rows[1].Shown)
	}
}
