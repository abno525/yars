package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A finding file that does not parse (written on the server by hand, past
// the push checks) opens as a page that names the file and says why, with
// 422, not a bare "internal error" (backlog, Core).
func TestUnreadableFindingPage(t *testing.T) {
	e := setup(t)
	p := filepath.Join(e.dir, "engagements", "acme", "findings", fdir, "finding.md")
	if err := os.WriteFile(p, []byte("---\nid: F-001\ntitle: SQL injection\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fpath, "/e/acme/f/001"} { // by folder and by number
		rec := e.do(t, "alice", "GET", path, nil, nil)
		b := rec.Body.String()
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(b, "<html") || strings.Contains(b, "internal error") {
			t.Fatalf("%s: code %d body:\n%s", path, rec.Code, b)
		}
		for _, want := range []string{"findings/" + fdir + "/finding.md", "unterminated front matter", `href="/e/acme"`} {
			if !strings.Contains(b, want) {
				t.Errorf("%s: the page lacks %q", path, want)
			}
		}
	}
}
