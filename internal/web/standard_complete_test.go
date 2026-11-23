package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The standard bulk bar has no complete: an unknown bulk action (400, 422
// for htmx), as before the simple workflow came, with nothing changed.
func TestStandardBulkCompleteUnknown(t *testing.T) {
	e := setup(t)
	code, body := e.bulkPost(t, "dora", url.Values{"action": {"complete"}, "id": {fdir}})
	if code != http.StatusUnprocessableEntity || !strings.Contains(body, "unknown bulk action") {
		t.Fatalf("code %d: %s", code, body)
	}
	if e.status(t) != "draft" {
		t.Fatalf("status %s", e.status(t))
	}
}
