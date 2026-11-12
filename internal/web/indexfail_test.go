package web

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// When the index cannot be read (here the main repository's HEAD is
// broken), pages that do not need it still open: the badges it feeds show
// none and the error is logged, instead of every page answering 500
// (backlog, M3).
func TestPagesOpenWhenIndexFails(t *testing.T) {
	e := setup(t)
	if err := os.Remove(filepath.Join(e.dir, ".git", "HEAD")); err != nil {
		t.Fatal(err)
	}
	e.srv.Store.Invalidate("")
	if _, err := e.srv.Index.Engagements(); err == nil {
		t.Fatal("the index still reads: the test breaks nothing")
	}
	for _, path := range []string{"/settings", "/notifications"} {
		rec := e.do(t, "alice", "GET", path, nil, nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<html") {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	// a page whose content is the engagement list fails, rather than show
	// none (M34 review)
	for _, path := range []string{"/", "/engagements", "/docs/git", "/inbox"} {
		if rec := e.do(t, "dora", "GET", path, nil, nil); rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	// the inbox's queues too: no queue rather than an empty one
	if rec := e.do(t, "dora", "GET", "/inbox?list=approve", nil, map[string]string{"HX-Request": "true"}); rec.Code != http.StatusInternalServerError {
		t.Errorf("a queue: %d", rec.Code)
	}
}

// When the database cannot give the inbox (here the board's seen marks are
// gone), other pages open without the badges, but the inbox fails rather
// than show nothing to do (M34 review).
func TestInboxWhenBadgesFail(t *testing.T) {
	e := setup(t)
	if _, err := e.srv.Store.DB().Exec("ALTER TABLE board_seen RENAME TO board_seen_gone"); err != nil {
		t.Fatal(err)
	}
	if rec := e.do(t, "dora", "GET", "/settings", nil, nil); rec.Code != http.StatusOK {
		t.Fatalf("settings: %d", rec.Code)
	}
	if rec := e.do(t, "dora", "GET", "/inbox", nil, nil); rec.Code != http.StatusInternalServerError {
		t.Fatalf("inbox: %d", rec.Code)
	}
}

// Admin › Rules shows its bench over the engagements: with no index it
// fails rather than offer none (M34 review).
func TestRulesPageWhenIndexFails(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, nil)
	if err := os.Remove(filepath.Join(e.dir, ".git", "HEAD")); err != nil {
		t.Fatal(err)
	}
	e.srv.Store.Invalidate("")
	if rec := e.do(t, "dora", "GET", "/admin/rules", nil, nil); rec.Code != http.StatusInternalServerError {
		t.Fatalf("%d", rec.Code)
	}
}
