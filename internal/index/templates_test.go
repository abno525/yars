package index

import (
	"testing"

	"github.com/abno525/yars/internal/finding"
)

// Template use is counted from the findings' "template" key, across
// engagements, once per table generation.
func TestTemplateUse(t *testing.T) {
	ix, s := fixture(t)
	err := s.SaveTemplate("hsts", alice, func(*finding.Finding) (*finding.Finding, error) { return s.NewTemplate("HSTS"), nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, eng := range []string{"acme", "acme", "other"} {
		if _, err := s.CreateFindingFrom(eng, "Missing HSTS", "hsts", alice); err != nil {
			t.Fatal(err)
		}
	}
	use, err := ix.TemplateUse()
	if err != nil {
		t.Fatal(err)
	}
	if use["hsts"] != 3 || len(use) != 1 {
		t.Fatalf("use %v", use)
	}
}
