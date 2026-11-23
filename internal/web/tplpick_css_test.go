package web

import (
	"strings"
	"testing"
)

// The Pick column of the template table holds its 18px radio between the
// 16px cell paddings, so the radio is never cut to an ellipsis.
func TestTemplatePickColumnFitsRadio(t *testing.T) {
	e := setup(t)
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	if !strings.Contains(css, ".tpltable th.c-pick { width: 56px; }") {
		t.Error("style.css: the template Pick column is not 56px wide")
	}
	if strings.Contains(css, ".tpltable th.c-pick { width: 48px; }") {
		t.Error("style.css: the template Pick column is still 48px, narrower than radio and paddings")
	}
}
