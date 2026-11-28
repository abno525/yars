package rules

import (
	"strings"
	"testing"
)

// Retarget changes the targets it is given and nothing else of a rule file:
// comments, other keys, other rules and rules that are off stay (pre1 7.11).
func TestRetarget(t *testing.T) {
	src := "# house rules\n- id: a\n  target: section:Impact # where it hurts\n  check: not-empty\n" +
		"- id: off\n  target: \"section:Impact\"\n  regex_forbid: 'TODO'\n  enabled: false\n" +
		"- id: row\n  target: details:Location\n  regex_forbid: x\n" +
		"- id: other\n  target: sections\n  regex_forbid: y\n"
	out, n, err := Retarget([]byte(src), map[string]string{"section:Impact": "section:Business impact", "details:Location": "details:Where"})
	if err != nil || n != 3 {
		t.Fatalf("%d rules changed, %v", n, err)
	}
	got := string(out)
	for _, want := range []string{"# house rules", "# where it hurts", "target: section:Business impact", "target: \"section:Business impact\"",
		"target: details:Where", "target: sections", "enabled: false", "regex_forbid: 'TODO'"} {
		if !strings.Contains(got, want) {
			t.Errorf("the file lacks %q:\n%s", want, got)
		}
	}
	rs, ps := Parse("r.yaml", out)
	if len(ps) != 0 || len(rs) != 4 || rs[0].Target != "section:Business impact" || rs[1].Target != "section:Business impact" || rs[1].On() || rs[2].Target != "details:Where" {
		t.Fatalf("%+v %+v", rs, ps)
	}
	// nothing to change: the same bytes, not a file written again
	same, n, err := Retarget([]byte(src), map[string]string{"section:Nope": "section:Other"})
	if err != nil || n != 0 || string(same) != src {
		t.Fatalf("a file without such a target changed: %d %v", n, err)
	}
}

// Two names that swap are one lookup per rule, and a name that YAML would
// read as structure is written as a value.
func TestRetargetSwapAndOddNames(t *testing.T) {
	src := "- id: a\n  target: section:A\n  check: not-empty\n- id: b\n  target: section:B\n  check: not-empty\n"
	out, n, err := Retarget([]byte(src), map[string]string{"section:A": "section:B", "section:B": "section:A"})
	rs, ps := Parse("r.yaml", out)
	if err != nil || n != 2 || len(ps) != 0 || rs[0].Target != "section:B" || rs[1].Target != "section:A" {
		t.Fatalf("swap: %d %v %+v %+v", n, err, rs, ps)
	}
	for _, name := range []string{"Impact: business", "It's \"bad\" # really", "- dash", "{x}", "a\nenabled: false"} {
		out, _, err := Retarget([]byte(src), map[string]string{"section:A": "section:" + name})
		rs, ps := Parse("r.yaml", out)
		if err != nil || len(ps) != 0 || len(rs) != 2 || rs[0].Target != "section:"+name || !rs[0].On() || rs[0].Check != "not-empty" {
			t.Errorf("%q: %v %+v %+v\n%s", name, err, rs, ps, out)
		}
	}
	// a file that is no list of rules is refused, not rewritten
	if _, _, err := Retarget([]byte("id: a\ntarget: section:A\n"), map[string]string{"section:A": "section:B"}); err == nil {
		t.Fatal("a file that is no list was rewritten")
	}
}
