package web

import (
	"net/http"
	"net/url"
	"strings"
)

// nextMax is the longest address the login goes on to.
const nextMax = 2000

// safeNext is s when it is a page of this site the login may go on to, else
// "". Only its form is judged, never whether the page exists or the account
// may see it: the page's own gates answer after the redirect. It is a path
// with an optional query and fragment: one leading "/", no "//" and no
// backslash anywhere (browsers read "/\" and "//" as the start of a host),
// no space or control character (browsers drop a tab or a line break inside
// an address, so "/\t/evil" is "//evil" to them; a line break would also end
// the Location header), and no scheme, host or user once parsed. The login's
// own pages are no place to go on to: a loop, or a route that takes a POST
// only.
func safeNext(s string) string {
	if len(s) < 2 || len(s) > nextMax || s[0] != '/' || strings.Contains(s, "//") || strings.Contains(s, `\`) {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] == 0x7f {
			return ""
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" || !strings.HasPrefix(u.Path, "/") {
		return ""
	}
	switch u.Path {
	case "/", "/login", "/logout", "/setup", "/password":
		return ""
	}
	return s
}

// loginURL is where a request without a session is sent: the login page,
// with the page to come back to as next when there is one. A GET or HEAD
// comes back to its own address. A form's POST comes back to the page it was
// on (the Referer's path, when the Referer is this site's): its own address
// takes a POST only.
func loginURL(r *http.Request) string {
	next := ""
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		next = r.URL.RequestURI()
	default:
		if ref, err := url.Parse(r.Header.Get("Referer")); err == nil && ref.Host != "" && ref.Host == r.Host && (ref.Scheme == "http" || ref.Scheme == "https") {
			next = ref.RequestURI()
		}
	}
	if next = safeNext(next); next == "" {
		return "/login"
	}
	return "/login?" + url.Values{"next": {next}}.Encode()
}
