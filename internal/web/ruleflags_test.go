package web

import (
	"context"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/rules"
)

// saveRule posts the rule editor as dora and fails unless the save went
// through.
func (e *env) saveRule(t *testing.T, form url.Values) {
	t.Helper()
	if rec := e.do(t, "dora", "POST", "/admin/rules/save", form, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("save %d\n%s", rec.Code, rec.Body.String())
	}
}

// The editor sets require_nonempty and the multiline flag: two boxes in the
// pattern block. They come back ticked, the flags as one group in front of
// the pattern, and the pattern field shows the pattern without them.
func TestAdminRuleMultilineAndNonEmpty(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	form := url.Values{"id": {"impact-first"}, "kind": {"pattern"}, "level": {"error"}, "target": {"section:Impact"},
		"mode": {"require"}, "pattern": {"^Impact"}, "multiline": {"1"}, "nonempty": {"1"}}
	e.saveRule(t, form)
	if f := e.ruleFile(t, "impact-first.yaml"); !strings.Contains(f, "regex_require: (?m)^Impact\n") || !strings.Contains(f, "require_nonempty: true") {
		t.Fatalf("file:\n%s", f)
	}
	ed := e.do(t, "dora", "GET", "/admin/rules?edit=impact-first", nil, nil).Body.String()
	for _, want := range []string{`name="pattern" value="^Impact"`, `name="multiline" value="1" checked`, `name="nonempty" value="1" checked`, `name="icase" value="1">`} {
		if !strings.Contains(ed, want) {
			t.Fatalf("editor lacks %s:\n%s", want, ed)
		}
	}
	// the engine: an empty part is a hit with the box, and the pattern
	// matches at a line's start
	r, _ := e.srv.Rules.Rule("impact-first")
	for body, hits := range map[string]int{"": 1, "First line\nImpact is high": 0, "No such line": 1} {
		d := rules.Doc{Sections: []rules.Section{{Name: "Impact", Body: body}}}
		if vs := e.srv.Rules.RunRule(context.Background(), r, d); len(vs) != hits {
			t.Errorf("body %q: %+v", body, vs)
		}
	}
	// both flags: one group; both boxes come back
	form.Set("old", "impact-first")
	form.Set("icase", "1")
	e.saveRule(t, form)
	if f := e.ruleFile(t, "impact-first.yaml"); !strings.Contains(f, "regex_require: (?im)^Impact\n") {
		t.Fatalf("both flags:\n%s", f)
	}
	ed = e.do(t, "dora", "GET", "/admin/rules?edit=impact-first", nil, nil).Body.String()
	for _, want := range []string{`name="pattern" value="^Impact"`, `name="multiline" value="1" checked`, `name="icase" value="1" checked`} {
		if !strings.Contains(ed, want) {
			t.Fatalf("editor lacks %s:\n%s", want, ed)
		}
	}
	// "Not match" has no empty-part rule: the key goes, the box stays on the
	// page in its place, unticked
	form.Set("mode", "forbid")
	e.saveRule(t, form)
	if f := e.ruleFile(t, "impact-first.yaml"); strings.Contains(f, "require_nonempty") || !strings.Contains(f, "regex_forbid: (?im)^Impact\n") {
		t.Fatalf("not match:\n%s", f)
	}
	ed = e.do(t, "dora", "GET", "/admin/rules?edit=impact-first", nil, nil).Body.String()
	if !strings.Contains(ed, `name="nonempty" value="1">`) {
		t.Fatalf("the box is gone or ticked:\n%s", ed)
	}
	// a save with the boxes unticked takes the flags and the key away
	form.Set("mode", "require")
	form.Del("multiline")
	form.Del("icase")
	form.Del("nonempty")
	e.saveRule(t, form)
	if f := e.ruleFile(t, "impact-first.yaml"); strings.Contains(f, "require_nonempty") || !strings.Contains(f, "regex_require: ^Impact\n") {
		t.Fatalf("unticked:\n%s", f)
	}
}

// Flags written by hand are read in any order and form; a flag group the
// boxes cannot show stays in the pattern as it was typed.
func TestAdminRuleHandWrittenFlags(t *testing.T) {
	e := setupSerial(t)
	for pattern, want := range map[string]struct {
		shown        string
		icase, multi bool
		saved        string
	}{
		"(?i)todo":      {"todo", true, false, "(?i)todo"},
		"(?m)^todo":     {"^todo", false, true, "(?m)^todo"},
		"(?mi)^todo":    {"^todo", true, true, "(?im)^todo"},
		"(?i)(?m)^todo": {"^todo", true, true, "(?im)^todo"},
		"(?m)(?i)^todo": {"^todo", true, true, "(?im)^todo"},
		"(?s)a.b":       {"(?s)a.b", false, false, "(?s)a.b"},
		"(?is)a.b":      {"(?is)a.b", false, false, "(?is)a.b"},
		"(?i)(?s)a.b":   {"(?s)a.b", true, false, "(?i)(?s)a.b"},
		"(?i:a)b":       {"(?i:a)b", false, false, "(?i:a)b"},
		"plain":         {"plain", false, false, "plain"},
	} {
		e.rules(t, "- id: hand\n  level: warning\n  target: title\n  regex_require: '"+pattern+"'\n  require_nonempty: true\n", nil)
		e.commitRules(t) // as a push of the file would
		f := e.srv.formOf(mustRule(t, e, "hand"))
		if f.Pattern != want.shown || f.ICase != want.icase || f.Multiline != want.multi || !f.NonEmpty || f.Mode != "require" {
			t.Errorf("%s: the editor shows %q, Aa %v, multiline %v, non-empty %v", pattern, f.Pattern, f.ICase, f.Multiline, f.NonEmpty)
			continue
		}
		// saved as it is shown, nothing changed by hand
		form := url.Values{"old": {"hand"}, "id": {"hand"}, "kind": {"pattern"}, "level": {"warning"}, "target": {"title"}, "mode": {"require"}, "pattern": {f.Pattern}, "nonempty": {"1"}}
		if f.ICase {
			form.Set("icase", "1")
		}
		if f.Multiline {
			form.Set("multiline", "1")
		}
		e.saveRule(t, form)
		if r := mustRule(t, e, "hand"); r.RegexRequire != want.saved || !r.RequireNonempty {
			t.Errorf("%s: saved as %q, require_nonempty %v", pattern, r.RegexRequire, r.RequireNonempty)
		}
	}
}

// A save that changes nothing is no error and no commit (the editor writes
// a rule back in its own form, so opening a rule and pressing Save is this).
func TestAdminRuleSaveUnchanged(t *testing.T) {
	e := setupSerial(t)
	e.rules(t, styleRules, map[string]string{"check.sh": "cat >/dev/null; echo '[]'\n"})
	head := func() string {
		out, err := exec.Command("git", "-C", e.dir, "rev-parse", "HEAD").Output()
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	form := url.Values{"id": {"no-todo"}, "kind": {"pattern"}, "level": {"warning"}, "target": {"sections"},
		"mode": {"forbid"}, "pattern": {"todo"}, "icase": {"1"}, "multiline": {"1"}, "message": {"No TODO left"}}
	e.saveRule(t, form)
	form.Set("old", "no-todo")
	at := head()
	e.saveRule(t, form)
	if head() != at {
		t.Fatal("a save that changed nothing made a commit")
	}
	// a script uploaded again with the same bytes, too
	fields := map[string]string{"id": "evidence", "kind": "script", "level": "warning", "target": ""}
	for i := range 2 {
		if rec := e.upload(t, "dora", "/admin/rules/save", fields, "evidence.sh", "#!/bin/sh\ncat >/dev/null\necho '[]'\n"); rec.Code != http.StatusSeeOther {
			t.Fatalf("upload %d: %d\n%s", i, rec.Code, rec.Body.String())
		}
		fields["old"] = "evidence"
	}
}

func mustRule(t *testing.T, e *env, id string) rules.Rule {
	t.Helper()
	r, ok := e.srv.Rules.Rule(id)
	if !ok {
		t.Fatalf("no rule %s", id)
	}
	return r
}
