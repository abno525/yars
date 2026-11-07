package web

import (
	"strings"
	"testing"
)

// The whole bulk bar is disabled at 0 selected, Clear too, unless a run's
// summary is there to clear; the script keeps it so as picks change.
func TestBulkClearDisabledAtZero(t *testing.T) {
	e := setup(t)
	b := e.do(t, "dora", "GET", "/inbox", nil, nil).Body.String()
	if !strings.Contains(b, `class="btn sm w96 bclear" data-bulk-clear disabled>Clear</button>`) {
		t.Fatalf("Clear enabled at 0:\n%s", between(b, `class="fbulk"`, "</section>"))
	}
	js := e.do(t, "dora", "GET", "/static/app.js", nil, nil).Body.String()
	if !strings.Contains(js, "clear.disabled = on.length === 0 && !ran;") {
		t.Fatal("app.js does not toggle Clear")
	}
}
