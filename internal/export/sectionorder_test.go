package export

import (
	"regexp"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/finding"
)

// A finding's sections are exported in the configured order, whatever order
// its file has them in (a push may write any). Sections the configuration
// does not name come after them, in file order; a name the file has twice
// stays together.
func TestSectionsExportInConfigOrder(t *testing.T) {
	f, err := finding.Parse([]byte("---\nid: F-001\ntitle: T\nseverity: low\n---\n\n" +
		"## Notes\n\nn1\n\n## Remediation\n\nr1\n\n## Appendix\n\na1\n\n## Description\n\nd1\n\n## Remediation\n\nr2\n\n## Impact\n\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	in := input(t)
	in.Findings = []*finding.Finding{f}
	in.Cfg.Sections = []string{"Description", "Impact", "Remediation"}
	const want = "Description Remediation Remediation Notes Appendix" // Impact is empty: left out
	h2 := regexp.MustCompile(`<h2>([^<]+)</h2>`)
	for what, x := range map[string]string{"XHTML": XHTML(in, false), "Report": Report(in)} {
		var got []string
		for _, m := range h2.FindAllStringSubmatch(x[strings.Index(x, "F-001"):], -1) {
			got = append(got, m[1])
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%s: sections %v, want %s", what, got, want)
		}
		if strings.Index(x, "r1") > strings.Index(x, "r2") {
			t.Errorf("%s: the two Remediation sections changed places", what)
		}
	}
	var got []string
	for _, m := range regexp.MustCompile(`(?m)^h2\. (.+)$`).FindAllStringSubmatch(jiraText(f, in), -1) {
		got = append(got, m[1])
	}
	if strings.Join(got, " ") != want {
		t.Errorf("Jira: sections %v, want %s", got, want)
	}
}
