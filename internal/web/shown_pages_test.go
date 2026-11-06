package web

import (
	"net/url"
	"strings"
	"testing"
)

// A signed-off finding shows as signed off on every page that tags its
// state, not only on the findings list: export, merge, duplicates, retest.
func TestSignedOffShownOnOtherPages(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	e.do(t, "bob", "POST", fpath+"/action/clear", url.Values{}, nil)
	f2, err := e.srv.Store.CreateFinding("acme", "SQL injection in search", e.authorOf(wAlice))
	if err != nil {
		t.Fatal(err)
	}
	tag := `<span class="tag status-signed-off">signed off</span>`
	for name, path := range map[string]string{
		"export": "/e/acme/export",
		"merge":  findingURL("acme", f2.Dir) + "/merge",
		"dups":   findingURL("acme", f2.Dir),
		"retest": "/e/acme/retest/new",
	} {
		b := e.do(t, "dora", "GET", path, nil, nil).Body.String()
		if !strings.Contains(b, tag) || strings.Contains(b, `<span class="tag status-verification">verification</span>`) {
			t.Errorf("%s page does not show signed off:\n%s", name, b)
		}
	}
}
