package web

import (
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"yars/internal/auth"
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
	deny := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no token", http.StatusUnauthorized)
	})
	e.srv.MCP, e.srv.Git = deny, deny
	e.h = e.srv.Handler()
	for _, c := range []struct{ method, path string }{{"POST", "/mcp"}, {"GET", "/git/acme.git/info/refs"}} {
		rec := e.do(t, "", c.method, c.path, nil, nil)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s: %d %v", c.method, c.path, rec.Code, rec.Header())
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
