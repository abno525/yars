package web

import (
	"strings"
	"testing"
)

// The admin tab bar is as on the admin boards (6.x): 180 x 44 tabs, the
// open one underlined in ink, not accent.
func TestAdminTabSize(t *testing.T) {
	e := setup(t)
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	for _, want := range []string{
		"  width: 180px; height: 44px; padding: 0 20px; flex: none;",
		".atab.on { color: var(--ink); font-weight: 700; box-shadow: inset 0 -3px 0 var(--ink); }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %s", want)
		}
	}
}
