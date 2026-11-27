package web

import (
	"strings"
	"testing"
)

// Copy works on a plain http address too, where the browser has no
// Clipboard API: app.js falls back to execCommand, says "Copy failed" when
// neither way worked, and selects the text then. A pin of the script: no
// click is run here. The copied text can be a secret (a token, a temporary
// password), so the only words a toast gets are the two fixed ones.
func TestCopyFallback(t *testing.T) {
	e := setup(t)
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	for _, w := range []string{
		"function yarsCopy(el, src)", "function yarsCopyOld(text, el)",
		"ok = document.execCommand('copy');",
		"} finally { ta.remove(); }",
		"if (!navigator.clipboard || !navigator.clipboard.writeText) { old(); return; }",
		"navigator.clipboard.writeText(text).then(function () { done(true); }).catch(old);",
		"if (ok) { yarsToast('Copied'); return; }",
		"yarsToast('Copy failed', true);",
		"if (s) s.selectAllChildren(src);",
	} {
		if !strings.Contains(app, w) {
			t.Errorf("app.js lacks %s", w)
		}
	}
	if strings.Contains(app, "|| !navigator.clipboard) return;") {
		t.Error("Copy still does nothing without the Clipboard API")
	}
	// the text is never part of a toast
	c := between(app, "function yarsCopy(el, src)", "\n}\n")
	if n := strings.Count(c, "yarsToast("); n != 2 || strings.Contains(c, "yarsToast(text") || strings.Contains(c, "+ text") {
		t.Errorf("yarsCopy's toasts:\n%s", c)
	}
}
