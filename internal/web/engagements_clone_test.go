package web

import (
	"net/http"
	"strings"
	"testing"
)

// The engagements list's Clone panel is a compact panel (small uppercase
// heading) with the commands full width under it (board 2.3).
func TestEngagementsClonePanel(t *testing.T) {
	e := setup(t)
	e.srv.Git = http.NotFoundHandler()
	b := e.do(t, "dora", "GET", "/engagements", nil, nil).Body.String()
	if !strings.Contains(b, `data-copy="clone-cmd"`) {
		t.Fatal("no clone panel")
	}
	for _, want := range []string{`<section class="panel compact">`, `<pre class="flush"><code id="clone-cmd">`, `class="btn secondary sm w96" data-copy="clone-cmd"`} {
		if !strings.Contains(b, want) {
			t.Errorf("clone panel lacks %s", want)
		}
	}
	css := e.do(t, "dora", "GET", "/static/style.css", nil, nil).Body.String()
	if !strings.Contains(css, ".panel pre.flush { margin: 0; padding: 16px 20px; }") {
		t.Error("style.css lacks the full-width pre")
	}
}
