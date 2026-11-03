package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"yars/internal/config"
)

func newAuth(t *testing.T) *Auth {
	t.Helper()
	h, err := HashPassword("secret")
	if err != nil {
		t.Fatal(err)
	}
	return New([]config.User{{Username: "alice", Role: "pentester", PasswordHash: h}})
}

func TestLoginOK(t *testing.T) {
	a := newAuth(t)
	tok, ok := a.Login("alice", "secret")
	if !ok || len(tok) != 64 {
		t.Fatalf("ok=%v tok=%q", ok, tok)
	}
}

func TestLoginBadPassword(t *testing.T) {
	a := newAuth(t)
	if _, ok := a.Login("alice", "wrong"); ok {
		t.Fatal("bad password accepted")
	}
	if _, ok := a.Login("mallory", "secret"); ok {
		t.Fatal("unknown user accepted")
	}
}

func TestRequireRedirects(t *testing.T) {
	a := newAuth(t)
	h := a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler reached") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("code=%d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestRequirePassesUserInContext(t *testing.T) {
	a := newAuth(t)
	tok, _ := a.Login("alice", "secret")
	var got config.User
	h := a.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = UserFrom(r.Context()) }))
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: tok})
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got.Username != "alice" || got.Role != "pentester" {
		t.Fatalf("got %+v", got)
	}
	a.Logout(tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatal("session survived logout")
	}
}
