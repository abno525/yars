// Package outbound has the HTTP client YARS sends with to a destination an
// admin configured (Confluence, Jira, a webhook): requests that carry a key,
// a signature and finding text. Such a request goes to the configured
// address only: a redirect to another host, another port or from https to
// http is refused, so neither the credentials nor the body follow it.
package outbound

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Refused is the error of a redirect that leaves the first request's
// address. It names the host only: a query string may carry a token.
type Refused struct{ Host string }

func (e *Refused) Error() string { return "redirect to " + e.Host + " refused" }

// Client is an http.Client with the timeout that follows redirects only on
// the address the request was made for (SameAddress).
func Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: SameAddress}
}

// origin is a URL's scheme, host name and port, the scheme's own port
// filled in.
func origin(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return u.Scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

// SameAddress is a CheckRedirect: it follows a redirect (ten at most, as
// the standard client) only to the scheme, host and port of the first
// request, and answers a *Refused for any other.
func SameAddress(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if len(via) > 0 && origin(req.URL) != origin(via[0].URL) {
		return &Refused{Host: req.URL.Host}
	}
	return nil
}
