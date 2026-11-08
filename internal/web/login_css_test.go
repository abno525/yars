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
