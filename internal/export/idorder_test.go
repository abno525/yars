package export

import (
	"slices"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// Findings of one severity are in the order of their numbers: F-999 before
// F-1000, F-7 before F-012.
func TestOrderedByNumber(t *testing.T) {
	in := Input{Cfg: config.Default()}
	for _, id := range []string{"F-1000", "F-012", "F-999", "F-7"} {
		in.Findings = append(in.Findings, mk(t, id, "T", "low", "complete", nil))
	}
	in.Findings = append(in.Findings, mk(t, "F-2000", "T", "high", "complete", nil))
	var got []string
	for _, f := range in.Ordered() {
		got = append(got, f.Meta.ID)
	}
	if want := []string{"F-2000", "F-7", "F-012", "F-999", "F-1000"}; !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}
