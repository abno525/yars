package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A title made only of bidi controls is empty once cleaned: the form says
// so (400 with the form), not a bare error from the store.
func TestNewFindingBidiOnlyTitle(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "alice", "POST", "/e/acme/findings/new", url.Values{"title": {"\u202e\u2066"}}, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Title is required.") {
		t.Fatalf("%d:\n%s", rec.Code, rec.Body)
	}
}

// A finding ID (F-001, as MCP, chat and reports name it) opens the finding
// like its number or folder does.
func TestFindingByID(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/e/acme/f/F-001", "/e/acme/f/F-1", "/e/acme/f/F-001/history"} {
		rec := e.do(t, "alice", "GET", p, nil, nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "SQL injection") {
			t.Errorf("%s: %d", p, rec.Code)
		}
	}
	if rec := e.do(t, "alice", "GET", "/e/acme/f/F-099", nil, nil); rec.Code != 404 {
		t.Errorf("unknown ID: %d", rec.Code)
	}
}
