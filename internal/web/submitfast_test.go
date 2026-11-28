package web

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A bulk Submit runs the pattern and built-in rules only, row by row: two
// drafts over an error-level script rule move at once, and the script does
// not run (before: every rule per row, and each row was refused with the
// script's error).
func TestBulkSubmitRunsNoScript(t *testing.T) {
	e := setupSerial(t)
	e.gateClean(t)
	d2 := e.second(t, "alice")
	st := e.srv.Store
	if err := st.SetReviewers("acme", d2, []string{"bob"}, wAlice); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateSeverity("acme", d2, "high", "", e.authorOf(wAlice)); err != nil {
		t.Fatal(err)
	}
	ran := filepath.Join(t.TempDir(), "ran")
	e.rules(t, "- id: scr\n  script: check.sh\n", map[string]string{"check.sh": "cat >/dev/null; echo run >> " + ran + `; echo '[{"message":"script says no","target":"title"}]'` + "\n"})
	code, b := e.bulkPost(t, "alice", url.Values{"action": {"submit"}, "id": {fdir, d2}})
	if code != 200 || !strings.Contains(summaryOf(b), "2 moved") || !strings.Contains(summaryOf(b), "0 skipped") {
		t.Fatalf("bulk submit: %d %s\n%s\n%s", code, summaryOf(b), frow(b, fdir), frow(b, d2))
	}
	if e.status(t) != "verification" || e.statusOf(t, "acme", d2) != "verification" {
		t.Fatalf("statuses %s, %s", e.status(t), e.statusOf(t, "acme", d2))
	}
	if out, _ := os.ReadFile(ran); len(out) != 0 {
		t.Fatalf("the script ran: %q", out)
	}
	// an error of a pattern rule still skips the row, with its words
	e.rules(t, "- id: title-word\n  target: title\n  regex_forbid: 'injection'\n  message: Avoid the word injection\n", nil)
	if err := st.Transition("acme", fdir, "take_back", "", wAlice); err != nil {
		t.Fatal(err)
	}
	code, b = e.bulkPost(t, "alice", url.Values{"action": {"submit"}, "id": {fdir}})
	if code != 200 || !strings.Contains(summaryOf(b), "0 moved") || !strings.Contains(frow(b, fdir), "Avoid the word injection") || e.status(t) != "draft" {
		t.Fatalf("bulk submit over a pattern error: %d %s\n%s", code, summaryOf(b), frow(b, fdir))
	}
}
