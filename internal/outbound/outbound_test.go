package outbound

import (
	"errors"
	"net/http"
	"testing"
)

// A redirect is followed only on the first request's scheme, host and port.
func TestSameAddress(t *testing.T) {
	for _, c := range []struct {
		first, next string
		ok          bool
	}{
		{"https://firm.atlassian.net/rest/api", "https://firm.atlassian.net/rest/api/", true},
		{"https://firm.atlassian.net/a", "https://FIRM.atlassian.net:443/b?x=1", true},
		{"http://yars.local/a", "http://yars.local:80/b", true},
		{"https://firm.atlassian.net/a", "https://evil.example/a", false},
		{"https://firm.atlassian.net/a", "https://sub.firm.atlassian.net/a", false}, // the standard client keeps the key here
		{"https://firm.atlassian.net/a", "https://firm.atlassian.net:8443/a", false},
		{"https://firm.atlassian.net/a", "http://firm.atlassian.net/a", false},
		{"http://127.0.0.1:8080/a", "http://127.0.0.1:9090/a", false},
	} {
		first, _ := http.NewRequest("POST", c.first, nil)
		next, _ := http.NewRequest("POST", c.next, nil)
		err := SameAddress(next, []*http.Request{first})
		var r *Refused
		if (err == nil) != c.ok || (err != nil && (!errors.As(err, &r) || r.Host != next.URL.Host || r.Error() != "redirect to "+next.URL.Host+" refused")) {
			t.Errorf("%s -> %s: %v", c.first, c.next, err)
		}
	}
	// a chain is held to the first address, and ends after ten
	first, _ := http.NewRequest("GET", "https://a.example/1", nil)
	mid, _ := http.NewRequest("GET", "https://a.example/2", nil)
	back, _ := http.NewRequest("GET", "https://b.example/3", nil)
	if err := SameAddress(back, []*http.Request{first, mid}); err == nil {
		t.Error("the second hop left the first address")
	}
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = first
	}
	if err := SameAddress(mid, via); err == nil {
		t.Error("an eleventh redirect was followed")
	}
	if c := Client(0); c.CheckRedirect == nil {
		t.Error("Client follows every redirect")
	}
}
