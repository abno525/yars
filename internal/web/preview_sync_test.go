package web

import (
	"strings"
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/render"
)

// bodyTextarea is the opening tag of an editor's text box.
func bodyTextarea(t *testing.T, html string) string {
	t.Helper()
	i := strings.Index(html, `<textarea name="body"`)
	if i < 0 {
		t.Fatalf("no editor:\n%s", html)
	}
	return html[i : i+strings.Index(html[i:], ">")+1]
}

// 5.8: the preview of an editor is one request at a time, the newest: a
// preview still under way is dropped when the next one is sent, so an older
// answer never lands over a newer one. A text over the Markdown cache's
// limit is rendered anew at every preview; its editor waits longer after a
// pause before it asks.
func TestPreviewSyncAndDelay(t *testing.T) {
	e := setup(t)
	for _, p := range []string{fpath + "/s/Impact/edit", "/e/acme/report/s/Scope/edit"} {
		tag := bodyTextarea(t, e.do(t, "alice", "GET", p, nil, nil).Body.String())
		if !strings.Contains(tag, `hx-sync="this:replace"`) {
			t.Errorf("%s: previews are not replaced by the next one: %s", p, tag)
		}
		// keyup: app.js fires it after Restore and Insert
		if !strings.Contains(tag, `hx-trigger="keyup changed delay:300ms, load"`) {
			t.Errorf("%s: trigger: %s", p, tag)
		}
	}
	long := strings.Repeat("Twelve words make a line of text that is long enough to count here.\n", render.MaxCached/60)
	if len(long) <= render.MaxCached {
		t.Fatalf("the text is %d bytes", len(long))
	}
	if err := e.srv.Store.UpdateSection("acme", "F-001-sql-injection", "Impact", long, "", gitrepo.Author{Name: "alice", Email: "alice@yars.local"}); err != nil {
		t.Fatal(err)
	}
	tag := bodyTextarea(t, e.do(t, "alice", "GET", fpath+"/s/Impact/edit", nil, nil).Body.String())
	if !strings.Contains(tag, `hx-trigger="keyup changed delay:1s, load"`) || !strings.Contains(tag, `hx-sync="this:replace"`) {
		t.Errorf("a long text is previewed as often as a short one: %s", tag)
	}
	if got := previewDelay(strings.Repeat("x", render.MaxCached)); got != "300ms" {
		t.Errorf("at the limit: %s", got)
	}
}
