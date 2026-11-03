package web

import (
	"net/url"
	"strings"
	"testing"
)

// section returns the HTML of the inbox list with the given heading.
func section(b, heading string) string {
	i := strings.Index(b, heading)
	if i < 0 {
		return ""
	}
	rest := b[i:]
	if j := strings.Index(rest[1:], "<h2"); j >= 0 {
		return rest[:j+1]
	}
	return rest
}

func TestInboxLists(t *testing.T) {
	e := setup(t)
	e.toVerification(t)

	b := e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String()
	if !strings.Contains(section(b, "Awaiting my review"), "SQL injection") {
		t.Fatalf("bob review list:\n%s", b)
	}
	if !strings.Contains(b, `class="badge">1<`) {
		t.Fatalf("bob badge:\n%s", b)
	}

	e.do(t, "bob", "POST", fpath+"/action/clear", url.Values{}, nil)
	b = e.do(t, "bob", "GET", "/inbox", nil, nil).Body.String()
	if strings.Contains(section(b, "Awaiting my review"), "SQL injection") || strings.Contains(b, `class="badge"`) {
		t.Fatalf("bob still pending:\n%s", b)
	}
	b = e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	if !strings.Contains(section(b, "Ready to approve"), "SQL injection") {
		t.Fatalf("dora approve list:\n%s", b)
	}

	e.do(t, "dora", "POST", fpath+"/action/return", url.Values{"reason": {"needs PoC"}}, nil)
	b = e.do(t, "alice", "GET", "/inbox", nil, nil).Body.String()
	if !strings.Contains(section(b, "Returned to me"), "SQL injection") {
		t.Fatalf("alice returned list:\n%s", b)
	}
	// badge also on other pages
	if b := e.do(t, "alice", "GET", "/e/acme", nil, nil).Body.String(); !strings.Contains(b, `class="badge">1<`) {
		t.Fatal("badge missing on engagement page")
	}
}
