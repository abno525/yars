package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestReportSectionsDefault(t *testing.T) {
	c, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.ReportSections, []string{"Executive summary", "Scope", "Methodology"}) {
		t.Fatalf("report sections %v", c.ReportSections)
	}
}

func TestSetStructureKeepsOtherKeys(t *testing.T) {
	dir := t.TempDir()
	raw := "# team config\nai:\n    provider: openai # local proxy\n    model: gpt\nsections: [A, B]\ncvss:\n    version: \"3.1\"\n    standard:\n        AV: N\n"
	c := Default()
	c.Sections = []string{"Description", "Fix"}
	c.DetailsRows = []string{"Location"}
	c.Severities = []string{"critical", "high", "medium", "low", "info", "note"}
	c.ReportSections = []string{"Summary"}
	c.CVSS.Standard = map[string]string{"AV": "L", "PR": "L"} // the others: no standard
	b, err := SetStructure([]byte(raw), c)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "# team config") || !strings.Contains(s, "# local proxy") || !strings.Contains(s, "model: gpt") {
		t.Fatalf("lost other keys:\n%s", s)
	}
	os.MkdirAll(filepath.Join(dir, ".yars"), 0o755)
	os.WriteFile(ConfigPath(dir), b, 0o644)
	got, err := Load(dir)
	if err != nil {
		t.Fatalf("%v\n%s", err, s)
	}
	if !slices.Equal(got.Sections, c.Sections) || !slices.Equal(got.DetailsRows, c.DetailsRows) || !slices.Equal(got.Severities, c.Severities) || !slices.Equal(got.ReportSections, c.ReportSections) {
		t.Fatalf("got %+v\n%s", got, s)
	}
	if got.CVSS.Standard["AV"] != "L" || got.CVSS.Standard["PR"] != "L" || len(got.CVSS.Standard) != 2 || got.AI.Model != "gpt" {
		t.Fatalf("standard %v ai %+v\n%s", got.CVSS.Standard, got.AI, s)
	}
	// an empty file works too
	if _, err := SetStructure(nil, c); err != nil {
		t.Fatal(err)
	}
}
