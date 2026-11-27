package index

import (
	"slices"
	"testing"
)

// A summary is cached per table generation, and it is built from the
// configured severities: a new configuration moves the generation, so the
// board's summary lists the new names in the new order. With no change a
// second call builds nothing.
func TestSummaryFollowsTheConfig(t *testing.T) {
	ix, s := fixture(t)
	keys := func(sum Summary) []string {
		var out []string
		for _, c := range sum.Severities {
			out = append(out, c.Key)
		}
		return out
	}
	sum, err := ix.Summary("acme")
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(sum); !slices.Equal(got, s.Config().Severities) {
		t.Fatalf("severities %v", got)
	}
	built := ix.summaryBuilds.Load()
	if _, err := ix.Summary("acme"); err != nil || ix.summaryBuilds.Load() != built {
		t.Fatalf("a second call built again (%v)", err)
	}
	gen, _ := ix.Gen()

	cfg := s.Config()
	cfg.Severities = []string{"urgent", "critical", "medium", "low"} // one added, two removed, another order
	s.SetConfig(cfg)
	sum, err = ix.Summary("acme")
	if err != nil {
		t.Fatal(err)
	}
	if got := keys(sum); !slices.Equal(got, cfg.Severities) {
		t.Fatalf("after the change the summary lists %v, want %v", got, cfg.Severities)
	}
	if g, _ := ix.Gen(); g == gen {
		t.Fatal("the generation did not move with the configuration")
	}
	built = ix.summaryBuilds.Load()
	if _, err := ix.Summary("acme"); err != nil || ix.summaryBuilds.Load() != built {
		t.Fatalf("a second call after the change built again (%v)", err)
	}
}
