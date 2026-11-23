package web

import (
	"strings"
	"testing"
)

// The retest Original panel head never shrinks its label or status tag: the
// finding reference takes what is left and is cut with an ellipsis.
func TestRetestOriginalHeadKeepsLabel(t *testing.T) {
	e := setup(t)
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	for _, want := range []string{
		".orig .panelname h2, .orig .panelname .tag { flex: none; }",
		".orig .panelname .mono { flex: 0 1 auto; min-width: 0; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %s", want)
		}
	}
}
