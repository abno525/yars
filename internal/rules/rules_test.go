package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"yars/internal/config"
)

func writeRules(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func doc() Doc {
	return Doc{ID: "F-001", Title: "SQL injection.", Severity: "high",
		Sections: []Section{{"Description", "Text with `code`."}, {"Location", "/login"}, {"Impact", ""}},
		Details:  map[string]string{"Location": "https://x/login", "Business impact": "Takeover"}}
}

func run(t *testing.T, rulesYAML string, d Doc) []Violation {
	t.Helper()
	s := Load(writeRules(t, map[string]string{"r.yaml": rulesYAML}))
	if len(s.Problems) > 0 {
		t.Fatalf("problems: %+v", s.Problems)
	}
	return s.Run(context.Background(), d, config.Default(), Fast, nil)
}

// A problem with a rule that has no id names the rule by its file and its
// place in it, as a problem with the whole file is named by the file
// (backlog, M5).
func TestProblemOfRuleWithoutID(t *testing.T) {
	s := Load(writeRules(t, map[string]string{"r.yaml": "- id: fine\n  regex_forbid: 'x'\n- level: error\n  regex_forbid: 'y'\n- regex_forbid: 'z'\n  levle: error\n"}))
	var rules []string
	for _, p := range s.Problems {
		rules = append(rules, p.Rule)
	}
	if strings.Join(rules, ",") != "rules/r.yaml#2,rules/r.yaml#3" {
		t.Fatalf("problems %+v", s.Problems)
	}
}

func TestLoadReportsBadRules(t *testing.T) {
	dir := writeRules(t, map[string]string{
		"bad.yaml": "- id: [unclosed\n",
		"mix.yaml": `
- id: good
  target: title
  regex_forbid: 'x'
- id: badre
  regex_forbid: '(['
- id: good
  regex_forbid: 'y'
- id: two
  regex_forbid: 'a'
  check: not-empty
- id: unknown
  check: no-such-check
- id: lvl
  level: fatal
  regex_forbid: 'a'
`,
	})
	s := Load(dir)
	if len(s.Rules) != 1 || s.Rules[0].ID != "good" {
		t.Fatalf("rules %+v", s.Rules)
	}
	all := ""
	for _, p := range s.Problems {
		if p.Level != "error" {
			t.Errorf("problem not error-level: %+v", p)
		}
		all += p.Rule + ": " + p.Message + "\n"
	}
	for _, want := range []string{"bad.yaml", "badre", "duplicate", "two", "no-such-check", "fatal"} {
		if !strings.Contains(all, want) {
			t.Errorf("problems lack %q:\n%s", want, all)
		}
	}
	// problems surface on every finding
	if vs := s.Run(context.Background(), doc(), config.Default(), Fast, nil); len(vs) < len(s.Problems) {
		t.Errorf("problems not reported by Run")
	}
	if s := Load(filepath.Join(dir, "missing")); len(s.Rules)+len(s.Problems) != 0 {
		t.Error("missing dir should be empty")
	}
}

func TestTyposAreProblems(t *testing.T) {
	s := Load(writeRules(t, map[string]string{"t.yaml": `
- id: typo-key
  levle: warning
  target: title
  regex_forbid: 'x'
- id: typo-target
  target: Title
  regex_forbid: 'x'
`}))
	all := ""
	for _, p := range s.Problems {
		all += p.Message + "\n"
	}
	if !strings.Contains(all, "levle") || !strings.Contains(all, "Title") {
		t.Fatalf("problems:\n%s", all)
	}
	// unknown section/details names are flagged by the engine (it knows the config)
	dir := writeRules(t, map[string]string{"u.yaml": "- id: loc\n  target: section:location\n  regex_forbid: 'x'\n- id: ok\n  target: details:Location\n  regex_forbid: 'x'\n"})
	e := NewEngine(dir, config.Default())
	msgs := ""
	for _, p := range e.Rules().Problems {
		msgs += p.Rule + ":" + p.Message + "\n"
	}
	if !strings.Contains(msgs, "loc:") || !strings.Contains(msgs, "section:location") || strings.Contains(msgs, "ok:") {
		t.Fatalf("engine problems:\n%s", msgs)
	}
}

func TestRegexForbid(t *testing.T) {
	vs := run(t, `
- id: title-no-dot
  target: title
  regex_forbid: '\.\s*$'
  message: Title must not end with a dot
`, doc())
	if len(vs) != 1 || vs[0].Quote != "." || vs[0].Target != "title" || vs[0].Message != "Title must not end with a dot" || vs[0].Level != "error" {
		t.Fatalf("got %+v", vs)
	}
}

func TestRegexRequire(t *testing.T) {
	r := `
- id: refs
  target: section:Location
  regex_require: '^https?://'
  level: warning
`
	vs := run(t, r, doc())
	if len(vs) != 1 || vs[0].Level != "warning" || vs[0].Target != "section:Location" || vs[0].Message != "refs" {
		t.Fatalf("got %+v", vs)
	}
	// empty target skipped unless require_nonempty
	if vs := run(t, "- id: x\n  target: section:Impact\n  regex_require: 'a'\n", doc()); len(vs) != 0 {
		t.Fatalf("empty target flagged: %+v", vs)
	}
	if vs := run(t, "- id: x\n  target: section:Impact\n  regex_require: 'a'\n  require_nonempty: true\n", doc()); len(vs) != 1 {
		t.Fatalf("require_nonempty: %+v", vs)
	}
}

func TestTargets(t *testing.T) {
	vs := run(t, "- id: bt\n  regex_forbid: '`'\n", doc()) // default target text
	if len(vs) != 2 || vs[0].Target != "section:Description" {
		t.Fatalf("text target: %+v", vs)
	}
	vs = run(t, "- id: loc\n  target: details:Location\n  regex_forbid: 'login'\n", doc())
	if len(vs) != 1 || vs[0].Target != "details:Location" {
		t.Fatalf("details target: %+v", vs)
	}
	vs = run(t, "- id: s\n  target: sections\n  regex_forbid: 'login'\n", doc())
	if len(vs) != 1 || vs[0].Target != "section:Location" {
		t.Fatalf("sections target: %+v", vs)
	}
	vs = run(t, "- id: d\n  target: details\n  regex_forbid: 'a'\n", doc())
	if len(vs) != 1 || vs[0].Target != "details:Business impact" {
		t.Fatalf("details target: %+v", vs)
	}
}

// The table check reads tables as the page renders them: lines in an
// indented code block are code, a table in a block quote is a table, and a
// last row written without pipes is a row (backlog, M5).
func TestTableCellsCheckAsRendered(t *testing.T) {
	for body, want := range map[string]string{
		"Code:\n\n    | a | `b` |\n    |---|---|\n    | c | d |\n":           "",
		"> | a | b |\n> |---|---|\n> | `c` | d |\n":                          "> | `c` | d |",
		"| a | b |\n|---|---|\n| c | d |\n`e` and f\n":                       "`e` and f",
		"| a | b |\n|---|---|\n| c | d |\n\n`e` is a paragraph, not a row\n": "",
	} {
		d := doc()
		d.Sections = []Section{{"Description", body}}
		d.Details = nil
		vs := run(t, "- id: tc\n  check: table-cells-no-backticks\n", d)
		var got []string
		for _, v := range vs {
			got = append(got, v.Quote)
		}
		if strings.Join(got, ";") != want {
			t.Errorf("%q: found %q, want %q", body, got, want)
		}
	}
}

func TestTableCellsCheck(t *testing.T) {
	d := doc()
	d.Sections = []Section{{"Description", "Para with `ok` code.\n\n| Field | Value |\n|---|---|\n| Param | `user` |\n| Pipe | `a|b` |\n\n```\n| x | `y` |\n```\n"}}
	d.Details = map[string]string{"Location": "`/login`", "Business impact": "fine"}
	vs := run(t, "- id: tc\n  check: table-cells-no-backticks\n", d)
	var targets []string
	for _, v := range vs {
		targets = append(targets, v.Target+"="+v.Quote)
	}
	got := strings.Join(targets, ";")
	if len(vs) != 3 || !strings.Contains(got, "section:Description=| Param | `user` |") || !strings.Contains(got, "details:Location") {
		t.Fatalf("got %s", got)
	}
}

func TestCVSSExplainedCheck(t *testing.T) {
	d := doc()
	d.CVSS = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
	d.CVSSReasons = map[string]string{"AC": "race"}
	vs := run(t, "- id: cv\n  check: cvss-explained\n", d)
	if len(vs) != 1 || vs[0].Target != "cvss" || !strings.Contains(vs[0].Message, "Confidentiality") {
		t.Fatalf("got %+v", vs)
	}
}

func TestViolationCap(t *testing.T) {
	d := doc()
	d.Sections = []Section{{"Description", strings.Repeat("x", 10000)}}
	vs := run(t, "- id: any\n  target: section:Description\n  regex_forbid: 'x'\n", d)
	if len(vs) != MaxPerRule {
		t.Fatalf("got %d", len(vs))
	}
	d.Sections[0].Body = strings.Repeat("y", 500)
	vs = run(t, "- id: long\n  target: section:Description\n  regex_forbid: 'y+'\n", d)
	if len(vs) != 1 || len([]rune(vs[0].Quote)) > 81 {
		t.Fatalf("quote not capped: %d", len(vs[0].Quote))
	}
}

func TestDisabledRule(t *testing.T) {
	if vs := run(t, "- id: x\n  enabled: false\n  target: title\n  regex_forbid: '.'\n", doc()); len(vs) != 0 {
		t.Fatalf("got %+v", vs)
	}
}

func TestRunSection(t *testing.T) {
	s := Load(writeRules(t, map[string]string{"r.yaml": `
- id: loc-bt
  target: section:Location
  regex_forbid: '` + "`" + `'
- id: title-dot
  target: title
  regex_forbid: '\.$'
`}))
	vs := s.RunSection(doc(), config.Default(), "Location", "uses `backtick")
	if len(vs) != 1 || vs[0].Rule != "loc-bt" {
		t.Fatalf("got %+v", vs)
	}
	if vs := s.RunSection(doc(), config.Default(), "Description", "uses `backtick`"); len(vs) != 0 {
		t.Fatalf("other section: %+v", vs)
	}
}

// The editor's hints see the body as it will be saved and as the panel's
// checks see it: line breaks as LF, no blank lines around it. A rule anchored
// at the end finds the same in both (backlog, M5).
func TestRunSectionSeesSavedBody(t *testing.T) {
	s := Load(writeRules(t, map[string]string{"r.yaml": `
- id: loc-dot
  target: section:Location
  regex_forbid: '\.$'
- id: loc-cr
  target: section:Location
  regex_forbid: "\r"
`}))
	typed := "\r\n/login.\r\n\r\n"
	vs := s.RunSection(doc(), config.Default(), "Location", typed)
	if len(vs) != 1 || vs[0].Rule != "loc-dot" {
		t.Fatalf("hints %+v", vs)
	}
	d := doc()
	d.Sections[1].Body = "/login."
	if panel := s.Run(context.Background(), d, config.Default(), Fast, nil); len(panel) != 1 || panel[0].Rule != "loc-dot" {
		t.Fatalf("panel %+v", panel)
	}
}

func TestErrors(t *testing.T) {
	vs := []Violation{{Level: "error", Message: "a"}, {Level: "warning", Message: "b"}}
	if e := Errors(vs); len(e) != 1 || e[0] != "a" {
		t.Fatalf("got %v", e)
	}
}
