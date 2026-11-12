package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"yars/internal/auth"
)

// A website request's body is at most 2 MiB, as an MCP request's is: a
// larger one is refused with 413 before any handler reads it, with or
// without a length, and before the login too. The uploads keep their own
// larger caps (backlog, Core).
func TestBodyLimit(t *testing.T) {
	e := setup(t)
	big := strings.Repeat("x", 3<<20)
	if rec := e.do(t, "alice", "POST", fpath+"/s/Impact", url.Values{"body": {big}}, nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a 3 MiB section: %d", rec.Code)
	}
	if rec := e.do(t, "", "POST", "/login", url.Values{"username": {"alice"}, "password": {big}}, nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a 3 MiB login: %d", rec.Code)
	}
	// no length (chunked): read up to the cap, not cut short, so a handler
	// never sees half a form
	chunked := func(body string) int {
		req := httptest.NewRequest("POST", fpath+"/s/Impact", io.MultiReader(strings.NewReader(body)))
		req.ContentLength = -1
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["alice"]})
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := chunked(url.Values{"body": {big}}.Encode()); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a 3 MiB section without a length: %d", code)
	}
	ref, _ := e.srv.Store.Finding("acme", fdir)
	if code := chunked(url.Values{"body": {"Small."}, "base": {e.srv.panelFor(ref, "Impact").Base}}.Encode()); code != http.StatusOK {
		t.Fatalf("a small section without a length: %d", code)
	}
	if ref, _ := e.srv.Store.Finding("acme", fdir); !strings.Contains(string(ref.F.Bytes()), "Small.") {
		t.Fatal("the small section was not saved")
	}
	// an attachment keeps its own 10 MiB cap
	if rec := e.sendFile(t, "alice", fpath+"/attachments", "big.txt", []byte(big)); rec.Code != http.StatusOK {
		t.Fatalf("a 3 MiB attachment: %d %s", rec.Code, rec.Body.String())
	}
	// only the upload routes themselves: a section, an action or a note
	// named like one is capped (review)
	for _, path := range []string{fpath + "/s/attachments", fpath + "/s/x%2Fattachments", fpath + "/action/redact", "/e/acme/board/n/1/redact"} {
		req := httptest.NewRequest("POST", path, strings.NewReader(url.Values{"body": {big}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: e.toks["alice"]})
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	// a backup to restore is not held to 2 MiB
	if rec := e.do(t, "dora", "POST", "/admin/system/restore", url.Values{"x": {big}}, nil); rec.Code == http.StatusRequestEntityTooLarge && strings.Contains(rec.Body.String(), "larger than 2 MiB") {
		t.Fatal("a restore upload was capped at 2 MiB")
	}
}
