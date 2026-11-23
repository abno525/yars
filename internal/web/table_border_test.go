package web

import (
	"strings"
	"testing"
)

// A table's last row has no bottom line, row headers (the CVSS reasons'
// Metric column) included, and row headers use the rows' soft line.
func TestTableLastRowNoBorder(t *testing.T) {
	e := setup(t)
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	for _, want := range []string{".table tbody tr:last-child > * { border-bottom: 0; }", ".reasons-view tbody th { border-bottom-color: var(--line-soft); }"} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %s", want)
		}
	}
}
