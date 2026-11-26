package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
)

const twoRules = `# house style
- id: a
  target: title
  regex_forbid: 'SQL'
# second
- id: b
  check: not-empty
  target: section:Impact
  level: warning
`

func TestSetRuleReplaceAppendRemove(t *testing.T) {
	f := false
	out, err := SetRule([]byte(twoRules), "a", &Rule{ID: "a2", Level: "error", Target: "title", RegexRequire: "^[A-Z]", Message: "Capital", Enabled: &f})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "id: a2") || strings.Contains(s, "id: a\n") || !strings.Contains(s, "regex_require:") || !strings.Contains(s, "enabled: false") {
		t.Fatalf("replace:\n%s", s)
	}
	if !strings.Contains(s, "check: not-empty") || !strings.Contains(s, "# second") {
		t.Fatalf("other rule or comment lost:\n%s", s)
	}
	if strings.Contains(s, "regex_forbid") || strings.Contains(s, "script:") {
		t.Fatalf("empty fields written:\n%s", s)
	}
	if strings.Index(s, "id: a2") > strings.Index(s, "id: b") {
		t.Fatalf("order changed:\n%s", s)
	}
	out, err = SetRule(out, "", &Rule{ID: "c", Script: "c.sh"})
	if err != nil || !strings.Contains(string(out), "id: c\n  script: c.sh") {
		t.Fatalf("append %v:\n%s", err, out)
	}
	rs, problems := Parse("r.yaml", out)
	if len(problems) != 0 || len(rs) != 3 {
		t.Fatalf("parse %+v %+v", rs, problems)
	}
	out, err = SetRule(out, "b", nil)
	if err != nil || strings.Contains(string(out), "id: b") {
		t.Fatalf("remove %v:\n%s", err, out)
	}
	if _, err := SetRule(out, "nope", nil); err == nil {
		t.Fatal("removing an unknown rule")
	}
	// removing the last rule empties the file
	one, _ := SetRule(nil, "", &Rule{ID: "x", Check: "not-empty"})
	if empty, err := SetRule(one, "x", nil); err != nil || empty != nil {
		t.Fatalf("last rule: %q %v", empty, err)
	}
}

func TestParseReportsProblems(t *testing.T) {
	_, problems := Parse("bad.yaml", []byte("- id: r\n  regex_forbid: '(['\n"))
	if len(problems) != 1 || !strings.Contains(problems[0].Message, "bad.yaml") {
		t.Fatalf("problems %+v", problems)
	}
}

func TestRuleValidate(t *testing.T) {
	if err := (Rule{ID: "r", RegexForbid: "(["}).Validate(); err == nil {
		t.Fatal("invalid regex accepted")
	}
	if err := (Rule{ID: "r", RegexForbid: "x", Target: "title"}).Validate(); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]Rule{"pattern": {RegexForbid: "x"}, "builtin": {Check: "not-empty"}, "script": {Script: "s.sh"}, "ai": {AI: "p"}}
	for want, r := range kinds {
		if got := r.KindName(); got != want {
			t.Errorf("%+v: kind %q, want %q", r, got, want)
		}
	}
	f := false
	if (Rule{}).On() != true || (Rule{Enabled: &f}).On() {
		t.Fatal("On")
	}
}

// The bench runs one rule, even a disabled one, scripts included.
func TestEngineRunRule(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "r.yaml"), []byte("- id: off\n  target: title\n  regex_forbid: 'SQL'\n  enabled: false\n- id: other\n  target: title\n  regex_forbid: 'injection'\n"), 0o644)
	script(t, dir, "s.sh", "cat >/dev/null; echo '[{\"message\":\"from script\",\"quote\":\"q\"}]'\n")
	e := NewEngine(dir, config.Default())
	r, ok := e.Rule("off")
	if !ok {
		t.Fatal("rule not found")
	}
	vs := e.RunRule(context.Background(), r, doc())
	if len(vs) != 1 || vs[0].Rule != "off" || vs[0].Quote != "SQL" {
		t.Fatalf("violations %+v", vs)
	}
	vs = e.RunRule(context.Background(), Rule{ID: "s", Level: "warning", Script: "s.sh"}, doc())
	if len(vs) != 1 || vs[0].Message != "from script" {
		t.Fatalf("script %+v", vs)
	}
	if _, ok := e.Rule("missing"); ok {
		t.Fatal("unknown rule found")
	}
}
