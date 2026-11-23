package web

import (
	"strings"
	"testing"
)

// The history page fits the window: only its list of changes scrolls. The
// list is the window less what stands above and below it: the 64 px top
// bar, main's 24 px top padding, the title (22 px crumbs, 8 gap, 28 px
// heading at 1.2 = 63.6), two 24 px gaps around the 24 px error slot, the
// panel's two borders and 48 px head, and main's 48 px bottom padding:
// 321.6 px. With 280 the page scrolled 42 px at 1440 x 900.
func TestHistoryListFitsWindow(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", fpath+"/history", nil, nil).Body.String(); !strings.Contains(b, `<section class="panel compact hevents">`) || !strings.Contains(b, `<div class="evlist flush">`) || !strings.Contains(b, `<div class="errslot">`) {
		t.Fatalf("history page:\n%s", b)
	}
	css := e.do(t, "alice", "GET", "/static/style.css", nil, nil).Body.String()
	for _, want := range []string{
		"position: sticky; top: 0; z-index: 10; height: 64px;",
		"main { max-width: 1760px; margin: 0 auto; padding: 24px 32px 48px; display: flex; flex-direction: column; gap: 24px; }",
		"h1 { margin: 0; font-size: 28px; font-weight: 700; line-height: 1.2; }",
		".idchip { height: 22px;",
		".titlecol { display: flex; flex-direction: column; gap: 8px;",
		".errslot { height: 24px;",
		".panel.compact .panelhead { height: 48px;",
		".evlist { display: flex; flex-direction: column; max-height: calc(100vh - 322px); overflow-y: auto; }",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("style.css lacks %s", want)
		}
	}
}
