package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// badNext are addresses the login never goes on to: another site in every
// spelling a browser reads as one, a script, a response header, the login's
// own pages.
var badNext = []string{
	"//evil.com", "///evil.com", `/\evil.com`, `\\evil.com`, `/\/evil.com`, `\/evil.com`,
	"https://evil.com", "http://evil.com/x", "http:evil.com", "javascript:alert(1)", "data:text/html,x", "evil.com", "e/acme",
	"", " /x", "/ /evil.com", "/\t/evil.com", "/\n/evil.com", "/x\r\nSet-Cookie: a=b", "/x\x00y", "/x\x7fy",
	"/e/acme?x=//evil.com", "/e/acme//f/001", `/e/acme?x=\evil`, "/e//evil.com",
	"/", "/login", "/login?next=/inbox", "/logout", "/setup", "/password",
	"/" + strings.Repeat("a", 5000),
}

// goodNext are pages of this site, kept as they are written.
var goodNext = []string{"/inbox", "/e/acme/f/001", "/e/acme?status=draft&q=sql", "/e/acme/f/001#chat", "/admin/rules?new=1", "/e/acme/board?n=L-001", "/loginx", "/e/acme/f/001/s/Proof%20of%20concept/edit"}

func TestSafeNext(t *testing.T) {
	for _, v := range badNext {
		if got := safeNext(v); got != "" {
			t.Errorf("safeNext(%q) = %q, want none", v, got)
		}
	}
	for _, v := range goodNext {
		if got := safeNext(v); got != v {
			t.Errorf("safeNext(%q) = %q", v, got)
		}
	}
}

// A page asked for without a session leads to the login with its address,
// the login page carries it, and a good login goes there.
func TestLoginReturnsToThePage(t *testing.T) {
	e := setup(t)
	rec := e.do(t, "", "GET", "/e/acme/f/001?x=1", nil, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login?next=%2Fe%2Facme%2Ff%2F001%3Fx%3D1" {
		t.Fatalf("a page without a session: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	// the start page needs no address
	if rec := e.do(t, "", "GET", "/", nil, nil); rec.Header().Get("Location") != "/login" {
		t.Fatalf("the start page: %q", rec.Header().Get("Location"))
	}
	// an htmx request from an open page keeps the page: 401, no redirect
	if rec := e.do(t, "", "GET", "/e/acme/f/001/workflow", nil, map[string]string{"HX-Request": "true"}); rec.Code != http.StatusUnauthorized || rec.Header().Get("Location") != "" || rec.Body.String() != "Session expired\n" {
		t.Fatalf("htmx without a session: %d %q", rec.Code, rec.Body.String())
	}
	field := `<input type="hidden" name="next" value="/e/acme/f/001?x=1">`
	b := e.do(t, "", "GET", "/login?next="+url.QueryEscape("/e/acme/f/001?x=1"), nil, nil).Body.String()
	if !strings.Contains(b, field) {
		t.Fatalf("the login page drops next:\n%s", b)
	}
	// a wrong password keeps it, a good one goes there
	rec = e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"bad"}, "next": {"/e/acme/f/001?x=1"}}, nil)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), field) {
		t.Fatalf("a failed login drops next: %d\n%s", rec.Code, rec.Body.String())
	}
	rec = e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"pw"}, "next": {"/e/acme/f/001?x=1"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/e/acme/f/001?x=1" || len(rec.Result().Cookies()) == 0 {
		t.Fatalf("a good login: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	for _, v := range goodNext {
		rec := e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"pw"}, "next": {v}}, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != v {
			t.Errorf("next %q: %d to %q", v, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// The login goes nowhere but this site: every other value of next ends at
// the start page, in the form's field and in the address alike, and is not
// drawn into the login page.
func TestLoginNextIsNoOpenRedirect(t *testing.T) {
	e := setup(t)
	for _, v := range badNext {
		rec := e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"pw"}, "next": {v}}, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
			t.Errorf("POST next %q: %d to %q", v, rec.Code, rec.Header().Get("Location"))
		}
		if len(rec.Header().Values("Set-Cookie")) != 1 {
			t.Errorf("POST next %q: cookies %q", v, rec.Header().Values("Set-Cookie"))
		}
		rec = e.do(t, "", "POST", "/login?next="+url.QueryEscape(v), url.Values{"username": {"alice"}, "password": {"pw"}}, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
			t.Errorf("POST ?next=%q: %d to %q", v, rec.Code, rec.Header().Get("Location"))
		}
		if b := e.do(t, "", "GET", "/login?next="+url.QueryEscape(v), nil, nil).Body.String(); strings.Contains(b, `name="next"`) {
			t.Errorf("GET ?next=%q: the login page carries it", v)
		}
		rec = e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"bad"}, "next": {v}}, nil)
		if strings.Contains(rec.Body.String(), `name="next"`) {
			t.Errorf("failed login, next %q: the login page carries it", v)
		}
	}
}

// A form posted without a session comes back to the page it was on: the
// address of a POST is no page, so the Referer's path is taken when the
// Referer is this site's.
func TestLoginNextOfAPost(t *testing.T) {
	e := setup(t)
	post := func(referer string) string {
		t.Helper()
		var hdr map[string]string
		if referer != "" {
			hdr = map[string]string{"Referer": referer}
		}
		rec := e.do(t, "", "POST", "/e/acme/f/001/action/submit", url.Values{}, hdr)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("referer %q: %d", referer, rec.Code)
		}
		return rec.Header().Get("Location")
	}
	for referer, want := range map[string]string{
		"http://example.com/e/acme/f/001":       "/login?next=%2Fe%2Facme%2Ff%2F001",
		"https://example.com/e/acme?status=all": "/login?next=%2Fe%2Facme%3Fstatus%3Dall",
		"":                                      "/login",
		"http://evil.com/e/acme/f/001":          "/login",
		"http://example.com.evil.com/x":         "/login",
		"http://example.com//evil.com":          "/login",
		"http://example.com/login":              "/login",
		"/e/acme/f/001":                         "/login",
		"::not a url":                           "/login",
	} {
		if got := post(referer); got != want {
			t.Errorf("referer %q: to %q, want %q", referer, got, want)
		}
	}
}

// next is checked on its form only: the login goes there, and the page's own
// gate answers. An account that is not on the team gets the stranger's 404.
func TestLoginNextLeaksNothing(t *testing.T) {
	e := setup(t)
	e.outsider(t)
	for _, to := range []string{"/e/acme", "/e/nosuch"} {
		rec := e.do(t, "", "POST", "/login", url.Values{"username": {"eve"}, "password": {"pw"}, "next": {to}}, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != to {
			t.Fatalf("eve, next %s: %d to %q", to, rec.Code, rec.Header().Get("Location"))
		}
		if rec := e.do(t, "eve", "GET", to, nil, nil); rec.Code != http.StatusNotFound || rec.Body.String() != "404 page not found\n" {
			t.Fatalf("eve at %s: %d %q", to, rec.Code, rec.Body.String())
		}
	}
}

// next is a path, and a path can hold a finding's folder name: it reaches
// no log line.
func TestLoginNextIsNotLogged(t *testing.T) {
	e := setupSerial(t)
	const marker = "zqnext7f3kq"
	to := "/e/acme/f/F-001-" + marker + "?q=" + marker
	e.log.Reset()
	e.do(t, "", "GET", to, nil, nil)
	e.do(t, "", "POST", "/e/acme/f/001/action/submit", url.Values{}, map[string]string{"Referer": "http://example.com" + to})
	e.do(t, "", "GET", "/login?next="+url.QueryEscape(to), nil, nil)
	e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"bad"}, "next": {to}}, nil)
	e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"pw"}, "next": {to}}, nil)
	if all := e.log.Text(); strings.Contains(all, marker) || !strings.Contains(all, "login failed") {
		t.Fatalf("next in the log (or no log at all):\n%s", all)
	}
}

// The reason forms of the workflow bar go through htmx, so an expired
// session leaves the typed reason in the page: the bar's forms say so, and
// the action answers an htmx press with HX-Redirect, a plain one with 303.
func TestReasonFormsThroughHtmx(t *testing.T) {
	e := setup(t)
	e.toVerification(t)
	b := e.do(t, "bob", "GET", fshort, nil, nil).Body.String()
	tag := between(b, `<form method="post" action="`+fshort+`/action/return"`, ">")
	for _, want := range []string{`hx-post="` + fshort + `/action/return"`, `hx-swap="none"`, `hx-disabled-elt="find button"`, `class="wfpanel return"`, `id="wf-return-reason"`} {
		if !strings.Contains(tag, want) {
			t.Errorf("the Return panel's form lacks %s: %s", want, tag)
		}
	}
	panel := between(b, `id="wf-return-reason"`, "</form>")
	for _, want := range []string{`<textarea name="reason" required rows="4" maxlength="4000">`, `aria-keyshortcuts="Control+Enter">Return</button>`, `data-reason-cancel="wf-return-reason">Cancel</button>`} {
		if !strings.Contains(panel, want) {
			t.Errorf("the Return panel lacks %s:\n%s", want, panel)
		}
	}
	// the buttons without a reason stay plain forms
	if sign := between(b, `class="wf-action" data-slot="clear"`, "</form>"); strings.Contains(sign, "hx-post") {
		t.Errorf("Sign off is an htmx form: %s", sign)
	}
	hx := map[string]string{"HX-Request": "true"}
	// without a session the press gets 401 and the page stays
	if rec := e.do(t, "", "POST", fshort+"/action/return", url.Values{"reason": {"Steps are incomplete"}}, hx); rec.Code != http.StatusUnauthorized || rec.Header().Get("HX-Redirect") != "" {
		t.Fatalf("no session: %d", rec.Code)
	}
	// a denied press: back to the finding, which shows the reason again
	rec := e.do(t, "bob", "POST", fshort+"/action/return", url.Values{"reason": {" "}}, hx)
	if rec.Code != http.StatusOK || rec.Header().Get("HX-Redirect") != fshort || rec.Header().Get("Location") != "" || rec.Body.Len() != 0 {
		t.Fatalf("a denied htmx press: %d HX-Redirect %q Location %q", rec.Code, rec.Header().Get("HX-Redirect"), rec.Header().Get("Location"))
	}
	if b := e.do(t, "bob", "GET", fshort, nil, nil).Body.String(); !strings.Contains(b, "reason is required") || e.status(t) != "verification" {
		t.Fatalf("the denial is not on the page:\n%s", b)
	}
	// a good press
	rec = e.do(t, "bob", "POST", fshort+"/action/return", url.Values{"reason": {"Steps are incomplete"}}, hx)
	if rec.Code != http.StatusOK || rec.Header().Get("HX-Redirect") != fshort || rec.Header().Get("Location") != "" || e.status(t) != "draft" {
		t.Fatalf("an htmx press: %d HX-Redirect %q status %s", rec.Code, rec.Header().Get("HX-Redirect"), e.status(t))
	}
	// a browser without script posts plain: 303 as before
	rec = e.do(t, "alice", "POST", fshort+"/action/withdraw", url.Values{"reason": {"duplicate"}}, nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != fshort || rec.Header().Get("HX-Redirect") != "" {
		t.Fatalf("a plain press: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
}
