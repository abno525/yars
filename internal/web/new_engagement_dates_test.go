package web

import (
	"net/url"
	"strings"
	"testing"
)

// Board 2.3 reserves an error line under ID and Name only: Start and End
// have none, so Team sits 24px higher; a date error shows under the pair.
func TestNewEngagementDatesNoErrorSlots(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/engagements/new", nil, nil).Body.String()
	for _, bad := range []string{`id="start-err"`, `id="end-err"`, `id="dates-err"`} {
		if strings.Contains(b, bad) {
			t.Errorf("fresh form has %s", bad)
		}
	}
	rec := e.do(t, "dora", "POST", "/engagements/new", url.Values{"id": {"beta"}, "name": {"Beta"}, "start": {"2026-05-02"}, "end": {"2026-05-01"}}, nil)
	b = rec.Body.String()
	i := strings.Index(b, `<span class="ferr" id="dates-err">`)
	if i < 0 || !strings.Contains(b, `aria-describedby="dates-err"`) {
		t.Fatalf("date error %d:\n%s", rec.Code, between(b, `id="new-engagement"`, "</form>"))
	}
	if j := strings.Index(b, `name="end"`); j < 0 || j > i {
		t.Fatal("the date error is not under the pair")
	}
}
