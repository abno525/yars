package web

import (
	"net/url"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/store"
)

// A reason over the store's cap is refused on the finding page, and the
// page that says so does not carry the whole text back.
func TestLongReasonRefusedOnPage(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	long := strings.Repeat("x", store.MaxReason+1)
	b := e.denied(t, "bob", fpath+"/action/return", url.Values{"reason": {long}})
	if !strings.Contains(b, "the reason is longer than 4000 characters") || e.status(t) != "verification" {
		t.Fatalf("return with a reason over the cap: status %s", e.status(t))
	}
	if strings.Contains(b, long) {
		t.Fatal("the refused reason came back whole")
	}
	if !strings.Contains(b, strings.Repeat("x", store.MaxReason)) {
		t.Fatal("the reason was not kept up to the cap")
	}
}
