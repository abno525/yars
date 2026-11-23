package web

import (
	"strings"
	"testing"
)

// The login card's disabled fields (a locked account's password) look
// disabled as on board 1.3: panel background, line border, off text.
func TestLoginDisabledFieldLook(t *testing.T) {
	e := setup(t)
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	want := ".barecard input:disabled { background: var(--panel); border-color: var(--line); color: var(--off-fg); }"
	if !strings.Contains(css, want) {
		t.Fatalf("style.css lacks %s", want)
	}
}

// The lockout alert goes while another username is typed (the script sets
// hidden): its display: flex must not keep it on screen. It hangs under
// the card, so nothing moves.
func TestLockoutAlertHides(t *testing.T) {
	e := setup(t)
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	if !strings.Contains(css, ".barealert[hidden] { display: none; }") {
		t.Fatal("a hidden lockout alert stays shown")
	}
	js := e.do(t, "dora", "GET", "/static/app.js", nil, nil).Body.String()
	if !strings.Contains(js, "box.hidden = !on;") {
		t.Fatal("the lockout script does not hide the alert")
	}
}
