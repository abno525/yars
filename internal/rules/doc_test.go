package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"yars/internal/finding"
)

// Scripts get the retest result and the files the finding's sections use.
func TestDocRetestAndAttachments(t *testing.T) {
	f := finding.New("F-001", "SQLi", "alice", []string{"Description", "Impact"})
	f.SetSection("Description", "![a](attachments/shot.png)\n\nsee attachments/req.txt and ![b](attachments/shot.png)")
	f.SetSection("Impact", "![c](https://x/y.png) [log](attachments/log-2.txt)")
	f.Meta.Retest = &finding.Retest{Source: "old/F-001", Result: "not_fixed"}
	d := DocOf(f)
	if d.RetestResult != "not_fixed" {
		t.Fatalf("retest %q", d.RetestResult)
	}
	if got := strings.Join(d.Attachments, ","); got != "shot.png,req.txt,log-2.txt" {
		t.Fatalf("attachments %q", got)
	}
	b, _ := json.Marshal(d)
	if !strings.Contains(string(b), `"retest_result":"not_fixed"`) || !strings.Contains(string(b), `"attachments":["shot.png","req.txt","log-2.txt"]`) {
		t.Fatalf("json %s", b)
	}
	// no retest, no files: empty values, never null
	b, _ = json.Marshal(DocOf(finding.New("F-002", "x", "alice", nil)))
	if !strings.Contains(string(b), `"retest_result":""`) || !strings.Contains(string(b), `"attachments":[]`) {
		t.Fatalf("json %s", b)
	}
}
