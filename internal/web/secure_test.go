package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/auth"
)

var wantHeaders = map[string]string{
	"X-Content-Type-Options":  "nosniff",
	"X-Frame-Options":         "DENY",
	"Referrer-Policy":         "same-origin",
	"Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
}

func TestSecureHeadersOnPages(t *testing.T) {
	e := setup(t)
	for _, c := range []struct{ user, path string }{{"", "/login"}, {"alice", "/e/acme"}} {
		rec := e.do(t, c.user, "GET", c.path, nil, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", c.path, rec.Code)
		}
		for h, want := range wantHeaders {
			if got := rec.Header().Get(h); got != want {
				t.Errorf("%s: %s = %q, want %q", c.path, h, got, want)
			}
		}
		if rec.Header().Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: HSTS without HTTPS", c.path)
		}
	}
}

// An attachment's own, stricter policy wins over the page policy.
func TestAttachmentKeepsOwnPolicy(t *testing.T) {
	e := setup(t)
	if rec := e.sendFile(t, "alice", fpath+"/attachments", "notes.txt", []byte("hello")); rec.Code != 200 {
		t.Fatalf("upload %d", rec.Code)
	}
	get := e.do(t, "bob", "GET", fpath+"/attachments/notes.txt", nil, nil)
	if p := get.Header().Get("Content-Security-Policy"); !strings.HasPrefix(p, "sandbox;") {
		t.Fatalf("attachment policy %q", p)
	}
}

// The git and MCP endpoints sit behind the same headers.
func TestGitAndMCPCarryNosniff(t *testing.T) {
	e := setup(t)
	// not http.Error: it sets nosniff itself, and the test would pass
	// without the middleware
	deny := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	e.srv.MCP, e.srv.Git = deny, deny
	e.h = e.srv.Handler()
	for _, c := range []struct{ method, path string }{{"POST", "/mcp"}, {"GET", "/git/acme.git/info/refs"}} {
		rec := e.do(t, "", c.method, c.path, nil, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: %d", c.method, c.path, rec.Code)
		}
		for h, want := range wantHeaders {
			if got := rec.Header().Get(h); got != want {
				t.Errorf("%s %s: %s = %q, want %q", c.method, c.path, h, got, want)
			}
		}
	}
}

func TestHSTSOnlyWithHTTPS(t *testing.T) {
	e := setup(t)
	if h := e.do(t, "", "GET", "/login", nil, nil).Header().Get("Strict-Transport-Security"); h != "" {
		t.Fatalf("HSTS by default: %q", h)
	}
	e.srv.HTTPS = true
	e.h = e.srv.Handler()
	if h := e.do(t, "", "GET", "/login", nil, nil).Header().Get("Strict-Transport-Security"); h != "max-age=31536000" {
		t.Fatalf("HSTS with HTTPS: %q", h)
	}
}

// Over HTTPS the session cookie a login sets is Secure.
func TestLoginCookieSecureWhenHTTPS(t *testing.T) {
	e := setup(t)
	e.srv.Auth.Secure = true
	rec := e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {"pw"}}, nil)
	var got *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.CookieName {
			got = c
		}
	}
	if got == nil || !got.Secure || got.Value == "" {
		t.Fatalf("login cookie %+v (status %d)", got, rec.Code)
	}
}

// A page load renews the session cookie, so an active user is not logged
// out 14 days after logging in; htmx requests from an open page do not.
func TestCookieRefreshedOnPageLoad(t *testing.T) {
	e := setup(t)
	session := func(rec *httptest.ResponseRecorder) *http.Cookie {
		for _, c := range rec.Result().Cookies() {
			if c.Name == auth.CookieName {
				return c
			}
		}
		return nil
	}
	c := session(e.do(t, "alice", "GET", "/", nil, nil))
	if c == nil || c.Value != e.toks["alice"] || c.MaxAge <= 0 {
		t.Fatalf("page load cookie %+v", c)
	}
	if c := session(e.do(t, "alice", "GET", "/e/acme", nil, map[string]string{"HX-Request": "true"})); c != nil {
		t.Fatalf("htmx request set %+v", c)
	}
	if c := session(e.do(t, "alice", "POST", fpath+"/chat", url.Values{"text": {"hi"}}, nil)); c != nil {
		t.Fatalf("a POST set %+v", c)
	}
}

// templates returns every template file by name.
func templates(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := templateFS.ReadFile(p)
		out[p] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The page's script policy allows no inline code: no on… handlers, no inline
// scripts, no style attributes.
func TestNoInlineHandlersInTemplates(t *testing.T) {
	handler := regexp.MustCompile(`\son[a-z]+\s*=`)
	script := regexp.MustCompile(`<script\b[^>]*>`)
	for name, src := range templates(t) {
		if m := handler.FindString(src); m != "" {
			t.Errorf("%s: inline handler %q", name, m)
		}
		for _, tag := range script.FindAllString(src, -1) {
			if !strings.Contains(tag, "src=") {
				t.Errorf("%s: inline script %q", name, tag)
			}
		}
		if strings.Contains(src, `style="`) {
			t.Errorf("%s: style attribute", name)
		}
	}
}

// htmx evaluates no code: no hx-on, no trigger filters.
func TestNoEvaluatedTriggers(t *testing.T) {
	trigger := regexp.MustCompile(`hx-trigger="[^"]*"`)
	for name, src := range templates(t) {
		if strings.Contains(src, "hx-on") {
			t.Errorf("%s: hx-on", name)
		}
		for _, m := range trigger.FindAllString(src, -1) {
			if strings.Contains(m, "[") {
				t.Errorf("%s: evaluated filter in %s", name, m)
			}
		}
	}
}

func TestHtmxNeverEvaluates(t *testing.T) {
	e := setup(t)
	b := e.do(t, "", "GET", "/login", nil, nil).Body.String()
	if !strings.Contains(b, `"allowEval":false`) || !strings.Contains(b, `"includeIndicatorStyles":false`) {
		t.Fatalf("htmx config lacks allowEval or includeIndicatorStyles:\n%s", between(b, "<head>", "</head>"))
	}
}

// What the pages keep in the browser does not pass to the next account on
// it: htmx keeps no page snapshots in localStorage (a Back to a pushed
// address loads the page again instead), a kept draft is stored under its
// account's name, and Log out removes the account's drafts (pre1 2.30).
func TestBrowserStorageIsPerAccount(t *testing.T) {
	e := setup(t)
	login := e.do(t, "", "GET", "/login", nil, nil).Body.String()
	for _, want := range []string{`"historyCacheSize":0`, `"refreshOnHistoryMiss":true`} {
		if !strings.Contains(between(login, "<head>", "</head>"), want) {
			t.Errorf("htmx config lacks %s", want)
		}
	}
	if strings.Contains(login, "data-user") {
		t.Error("the login page names an account")
	}
	page := e.do(t, "alice", "GET", fpath, nil, nil).Body.String()
	if tag := between(page, "<html", ">"); !strings.Contains(tag, ` data-user="alice"`) {
		t.Errorf("the page does not name its account for the draft key: %s>", tag)
	}
	if !strings.Contains(page, `<form method="post" action="/logout">`) {
		t.Error("the Log out form app.js hooks is gone")
	}
	js := e.do(t, "alice", "GET", staticPrefix()+"/app.js", nil, nil).Body.String()
	for _, want := range []string{
		// the key: yars-draft:<user>:<save URL>
		`'yars-draft:' + yarsUser() + ':'`, `getAttribute('data-user')`,
		// snapshots and drafts of an earlier version are removed at load
		`localStorage.removeItem('htmx-history-cache')`, `'yars-draft:/'`,
		// Log out removes this account's drafts
		`form[action="/logout"]`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
	// the draft is written when the session has expired: a 401 must not be
	// what removes it
	i := strings.Index(js, "function yarsExpired()")
	if i < 0 || strings.Contains(js[i:i+900], "removeItem") {
		t.Error("an expired session removes drafts")
	}
}

// Comment and confirm buttons are wired in app.js through data attributes.
func TestCommentAndConfirmHooks(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", "/e/acme/f/001", nil, nil).Body.String(); !strings.Contains(b, `data-comment="Description"`) {
		t.Fatal("the finding page has no data-comment button")
	}
	if b := e.do(t, "dora", "GET", "/", nil, nil).Body.String(); !strings.Contains(b, `data-confirm="Archive ACME Web?"`) {
		t.Fatal("the engagements list has no data-confirm Archive button")
	}
	js := e.do(t, "alice", "GET", staticPrefix()+"/app.js", nil, nil).Body.String()
	for _, want := range []string{"data-comment", "data-confirm", "htmx:beforeRequest", "yars:enter", "yars:rowclick"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
}
