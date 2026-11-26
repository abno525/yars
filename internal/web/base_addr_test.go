package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/auth"
)

// The clone and MCP addresses a page shows come from base_url when it is
// set; without it the scheme is the server's own (--https or a certificate),
// never a header any client can send, and the host is the request's.
func TestShownAddressIgnoresClientHeaders(t *testing.T) {
	e := setup(t)
	e.srv.Git = http.NotFoundHandler()
	get := func(path, host string, hdr map[string]string) string {
		t.Helper()
		req := httptest.NewRequest("GET", path, nil)
		if host != "" {
			req.Host = host
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["alice"]})
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("GET %s: %d", path, rec.Code)
		}
		return rec.Body.String()
	}
	proto := map[string]string{"X-Forwarded-Proto": "https"}
	// a client's header does not make the address https
	if b := get("/", "", proto); !strings.Contains(b, "git clone http://example.com/git/yars") || strings.Contains(b, "https://example.com") {
		t.Fatal("the header decided the scheme")
	}
	if b := get("/docs/mcp", "", proto); !strings.Contains(b, "http://example.com/mcp") || strings.Contains(b, "https://example.com/mcp") {
		t.Fatal("the header decided the MCP address's scheme")
	}
	// --https does
	e.srv.HTTPS = true
	if b := get("/e/acme", "", nil); !strings.Contains(b, "git clone https://example.com/git/e/acme") {
		t.Fatal("--https without a header: no https address")
	}
	e.srv.HTTPS = false
	// base_url wins over the request's Host, on every page that shows an address
	c := e.srv.conf()
	c.BaseURL = "https://yars.example.com"
	e.srv.setConfig(c)
	for path, want := range map[string]string{
		"/":         "git clone https://yars.example.com/git/yars",
		"/e/acme":   "git clone https://yars.example.com/git/e/acme",
		"/docs/mcp": "https://yars.example.com/mcp",
		"/docs/git": "https://alice@yars.example.com/git/yars",
	} {
		b := get(path, "evil.example", proto)
		if !strings.Contains(b, want) || strings.Contains(b, "evil.example") {
			t.Fatalf("%s with base_url and another Host: want %q", path, want)
		}
	}
}
