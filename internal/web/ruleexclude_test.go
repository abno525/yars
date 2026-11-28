package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// The editor sets exclude: code with one more box in the pattern block. The
// key survives the on/off switch and a save with the box; a save without the
// box takes it away, and a rule that is no pattern never gets it (pre1 7.8).
func TestAdminRuleExcludeCode(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	form := url.Values{"id": {"no-password"}, "kind": {"pattern"}, "level": {"warning"}, "target": {"sections"},
		"mode": {"forbid"}, "pattern": {"password"}, "nocode": {"1"}}
	e.saveRule(t, form)
	if f := e.ruleFile(t, "no-password.yaml"); !strings.Contains(f, "exclude: code\n") {
		t.Fatalf("file:\n%s", f)
	}
	if r := mustRule(t, e, "no-password"); r.Exclude != "code" {
		t.Fatalf("rule %+v", r)
	}
	const ticked, unticked = `name="nocode" value="1" checked>Skip code`, `name="nocode" value="1">Skip code`
	if ed := e.do(t, "dora", "GET", "/admin/rules?edit=no-password", nil, nil).Body.String(); !strings.Contains(ed, ticked) {
		t.Fatalf("the box is not ticked:\n%s", ed)
	}
	// the box is in a new rule's form too, in its place, unticked
	if ed := e.do(t, "dora", "GET", "/admin/rules?new=1", nil, nil).Body.String(); !strings.Contains(ed, unticked) {
		t.Fatalf("a new rule has no box:\n%s", ed)
	}
	// off and on again: the file keeps the key
	for _, on := range []string{"0", "1"} {
		if rec := e.do(t, "dora", "POST", "/admin/rules/toggle", url.Values{"id": {"no-password"}, "on": {on}}, nil); rec.Code != http.StatusSeeOther {
			t.Fatalf("toggle %s: %d\n%s", on, rec.Code, rec.Body.String())
		}
		if f := e.ruleFile(t, "no-password.yaml"); !strings.Contains(f, "exclude: code\n") {
			t.Fatalf("after on=%s the key is gone:\n%s", on, f)
		}
	}
	// a pattern the text must match keeps it as well
	form.Set("old", "no-password")
	form.Set("mode", "require")
	e.saveRule(t, form)
	if f := e.ruleFile(t, "no-password.yaml"); !strings.Contains(f, "exclude: code\n") || !strings.Contains(f, "regex_require: password\n") {
		t.Fatalf("match mode:\n%s", f)
	}
	// saved without the box: the key goes
	form.Del("nocode")
	e.saveRule(t, form)
	if f := e.ruleFile(t, "no-password.yaml"); strings.Contains(f, "exclude") {
		t.Fatalf("unticked:\n%s", f)
	}
	if ed := e.do(t, "dora", "GET", "/admin/rules?edit=no-password", nil, nil).Body.String(); !strings.Contains(ed, unticked) {
		t.Fatalf("the box is gone or ticked:\n%s", ed)
	}
	// another kind posted with the box: the key is a pattern's alone
	form.Set("nocode", "1")
	form.Set("kind", "ai")
	form.Set("ai", "Be short.")
	e.saveRule(t, form)
	if f := e.ruleFile(t, "no-password.yaml"); strings.Contains(f, "exclude") || !strings.Contains(f, "ai: Be short.") {
		t.Fatalf("an AI rule with the key:\n%s", f)
	}
}
