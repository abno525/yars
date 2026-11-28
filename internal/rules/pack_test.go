package rules

import (
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// The starter rules load without a problem, come turned off, and need
// nothing a new data folder lacks: no script, no AI provider, and no target
// that names a section or a details row of the configuration (such a target
// is a warning line on the Rules page when the configuration has other
// names).
func TestStarterRules(t *testing.T) {
	if _, problems := Parse("starter.yaml", starterYAML); len(problems) != 0 {
		t.Fatalf("the starter file has problems: %+v", problems)
	}
	rs := Starter()
	if len(rs) < 5 {
		t.Fatalf("%d starter rules", len(rs))
	}
	seen := map[string]bool{}
	for _, r := range rs {
		if r.On() || r.File != "" {
			t.Errorf("%s: on %v, file %q", r.ID, r.On(), r.File)
		}
		if r.Script != "" || r.AI != "" {
			t.Errorf("%s needs a script or a provider", r.ID)
		}
		if strings.Contains(r.Target, ":") {
			t.Errorf("%s: target %q names a part of the configuration", r.ID, r.Target)
		}
		if r.Message == "" || seen[r.ID] {
			t.Errorf("%s: no message, or twice", r.ID)
		}
		seen[r.ID] = true
		if err := r.Validate(); err != nil {
			t.Errorf("%s: %v", r.ID, err)
		}
	}
	// what the rules do on a text, once turned on
	d := Doc{Title: "SQL injection in the export.", Sections: []Section{{Name: "Impact", Body: "We read the  users table. TODO\n\n```\nTODO in code\n```"}, {Name: "Steps", Body: ""}}}
	got := map[string]int{}
	for _, r := range rs {
		r.Enabled = nil
		for _, v := range (&Set{Rules: []Rule{r}}).Run(t.Context(), d, config.Config{}, Fast, nil) {
			got[v.Rule]++
		}
	}
	for id, want := range map[string]int{"title-no-trailing-dot": 1, "no-placeholder": 1, "no-first-person": 1, "no-double-space": 1, "sections-not-empty": 1, "title-not-too-long": 0} {
		if got[id] != want {
			t.Errorf("%s: %d hits, want %d (all: %v)", id, got[id], want, got)
		}
	}
}

// A pack is a list of rules: what Pack writes, ParsePack reads back, rules
// that are off too.
func TestPackRoundTrip(t *testing.T) {
	off := false
	in := []Rule{
		{ID: "a", Level: "warning", Target: "title", RegexForbid: `\.$`, Message: "No dot: here"},
		{ID: "b", Level: "error", Target: "section:Impact", RegexRequire: "(?m)^Impact", RequireNonempty: true, Exclude: ExcludeCode, Enabled: &off},
		{ID: "c", Level: "error", Target: "sections", Check: "not-empty"},
		{ID: "d", Level: "warning", Script: "check.sh"},
		{ID: "e", Level: "warning", Target: "sections", AI: "Expand every acronym.\nOn first use."},
	}
	b, err := Pack(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParsePack(b)
	if err != nil || len(out) != len(in) {
		t.Fatalf("%v %+v\n%s", err, out, b)
	}
	for i, r := range out {
		w := in[i]
		if r.ID != w.ID || r.Level != w.Level || r.Target != w.Target || r.RegexForbid != w.RegexForbid || r.RegexRequire != w.RegexRequire || r.RequireNonempty != w.RequireNonempty ||
			r.Exclude != w.Exclude || r.Check != w.Check || r.Script != w.Script || r.AI != w.AI || r.Message != w.Message || r.On() != w.On() || r.File != "" {
			t.Errorf("rule %d: %+v, want %+v", i, r, w)
		}
	}
	if b, err := Pack(nil); err != nil || strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("no rules: %q %v", b, err)
	}
}

// One problem refuses the whole pack, with words that name it.
func TestParsePackRefuses(t *testing.T) {
	for name, c := range map[string]struct{ pack, want string }{
		"no list":      {"id: a\nregex_forbid: x\n", "not a list of rules"},
		"a scalar":     {"- just a word\n", "not a list of rules"},
		"no yaml":      {"- id: [a\n", "not YAML"},
		"empty":        {"", "not a list of rules"},
		"an empty one": {"[]\n", "no rules"},
		"unknown key":  {"- id: a\n  regex_forbid: x\n  levle: error\n", "unknown field(s) levle"},
		"bad regex":    {"- id: a\n  regex_forbid: '(['\n", "missing closing ]"},
		"two kinds":    {"- id: a\n  regex_forbid: x\n  check: not-empty\n", "needs exactly one of"},
		"no kind":      {"- id: a\n", "needs exactly one of"},
		"no id":        {"- regex_forbid: x\n", "rule without id"},
		"twice":        {"- id: a\n  regex_forbid: x\n- id: a\n  regex_forbid: y\n", "duplicate rule id a"},
		"bad level":    {"- id: a\n  level: fatal\n  regex_forbid: x\n", "must be error or warning"},
		"bad target":   {"- id: a\n  target: body\n  regex_forbid: x\n", "unknown target"},
		"bad check":    {"- id: a\n  check: nope\n", "unknown check"},
	} {
		rs, err := ParsePack([]byte(c.pack))
		if err == nil || !strings.Contains(err.Error(), c.want) || rs != nil {
			t.Errorf("%s: %v %+v (want %q)", name, err, rs, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "(pack)") {
			t.Errorf("%s: the words name the pack as a file: %v", name, err)
		}
	}
}
