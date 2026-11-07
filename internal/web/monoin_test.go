package web

import (
	"strings"
	"testing"
)

// A .monoin field (the new engagement's ID, a lead's host) is set in the
// mono font: the rule must outrank the base text-input rule
// (input:not([type=checkbox]):not([type=radio]), specificity 0,2,1).
func TestMonoInputOutranksBaseInput(t *testing.T) {
	e := setup(t)
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	want := `.monoin, input.monoin:not([type="checkbox"]):not([type="radio"]) { font: 500 14px var(--mono); }`
	if !strings.Contains(css, want) {
		t.Errorf("style.css lacks %s", want)
	}
}
