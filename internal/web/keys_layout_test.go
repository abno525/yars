package web

import (
	"strings"
	"testing"
)

// 5.4: on a layout without Latin letters (Cyrillic, Greek) a letter key
// counts as the Latin letter of its place, so Ctrl+S saves and Ctrl+K opens
// Go to. A Latin layout keeps its own letters (Dvorak, AZERTY): the place
// is read only for a letter key whose character is not ASCII. No test runs
// the script: these are pins of its text.
func TestKeysNonLatinLayout(t *testing.T) {
	e := setup(t)
	app := e.do(t, "alice", "GET", "/static/app.js", nil, nil).Body.String()
	fn := jsFunc(t, app, "function yarsLetter(evt)", "\n}\n")
	for _, want := range []string{"evt.code", "/^Key[A-Z]$/", "charCodeAt(0) > 127", "AltGraph", "evt.code.charAt(3)"} {
		if !strings.Contains(fn, want) {
			t.Errorf("yarsLetter lacks %s:\n%s", want, fn)
		}
	}
	// Go to's Ctrl+K goes through it
	i := strings.Index(app, "yarsGotoOpen();\n    return;")
	if i < 0 {
		t.Fatal("no Ctrl+K handler")
	}
	if head := app[i-300 : i]; strings.Contains(head, "evt.key === 'k'") || !strings.Contains(head, "yarsLetter(evt)") {
		t.Errorf("Ctrl+K reads evt.key alone:\n%s", head)
	}
	keys := e.do(t, "alice", "GET", "/static/keys.js", nil, nil).Body.String()
	if fn := jsFunc(t, keys, "function yarsKeyOf(evt)", "\n}\n"); strings.Contains(fn, "= evt.key") || !strings.Contains(fn, "yarsLetter(evt)") {
		t.Errorf("yarsKeyOf reads evt.key alone:\n%s", fn)
	}
}
