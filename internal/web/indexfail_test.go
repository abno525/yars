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
}
