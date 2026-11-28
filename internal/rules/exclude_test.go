package rules

import (
	"context"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
)

// codeBody has the word password once in prose, once in a fenced block
// (and once as the fence's language), once in an indented block and once in
// a code span.
const codeBody = "The password is weak.\n\n```password\nPOST /login\nuser=a&password=b\n```\n\n    grep password /etc/passwd\n\nSend `password` again.\n"

func codeDoc(body string) Doc {
	return Doc{ID: "F-001", Title: "Weak password", Sections: []Section{{"Description", body}},
		Details: map[string]string{"Location": "`password` field"}}
}

// A pattern rule with exclude: code does not match inside a fenced block,
// an indented block or a code span of a section; without the key it matches
// the Markdown as written (pre1 7.8).
func TestExcludeCode(t *testing.T) {
	const plain = "- id: pw\n  target: sections\n  regex_forbid: 'password'\n"
	d := codeDoc(codeBody)
	if vs := run(t, plain, d); len(vs) != 5 {
		t.Fatalf("without the key: %d hits, want 5: %+v", len(vs), vs)
	}
	vs := run(t, plain+"  exclude: code\n", d)
	if len(vs) != 1 || vs[0].Target != "section:Description" || vs[0].Quote != "password" {
		t.Fatalf("with the key: %+v", vs)
	}
	// the title and a details row are no Markdown: matched as written
	vs = run(t, "- id: pw\n  regex_forbid: '(?i)password'\n  exclude: code\n", d)
	var places []string
	for _, v := range vs {
		places = append(places, v.Target)
	}
	if strings.Join(places, ",") != "title,section:Description,details:Location" {
		t.Fatalf("places %v", places)
	}
}

// The quote of a hit is cut from the section's own text, also when the
// match runs over a code block; a match that lies in code alone is no hit.
func TestExcludeCodeQuoteIsTheText(t *testing.T) {
	body := "before\n\n```\nsecret  x\n```\n\nafter"
	d := codeDoc(body)
	vs := run(t, "- id: span\n  target: sections\n  regex_forbid: '(?s)before.*after'\n  exclude: code\n", d)
	if len(vs) != 1 {
		t.Fatalf("%+v", vs)
	}
	// the quote is what the page shows: the text, cut as every quote
	if want := quote(body); vs[0].Quote != want || !strings.Contains(vs[0].Quote, "secret  x") {
		t.Fatalf("quote %q, want %q", vs[0].Quote, want)
	}
	// two spaces are in the code only: the blanks that stand for code are
	// never a hit of their own
	if vs := run(t, "- id: sp\n  target: sections\n  regex_forbid: '  +'\n  exclude: code\n", d); len(vs) != 0 {
		t.Fatalf("a hit inside code: %+v", vs)
	}
	// ^ and $ keep their lines with (?m)
	vs = run(t, "- id: line\n  target: sections\n  regex_forbid: '(?m)^after$'\n  exclude: code\n", d)
	if len(vs) != 1 || vs[0].Quote != "after" {
		t.Fatalf("%+v", vs)
	}
}

// A fence that is never closed makes the rest of the section code, as the
// page shows it.
func TestExcludeCodeUnclosedFence(t *testing.T) {
	d := codeDoc("TODO one\n\n```\nTODO two\n\nTODO three")
	vs := run(t, "- id: todo\n  target: sections\n  regex_forbid: 'TODO \\w+'\n  exclude: code\n", d)
	if len(vs) != 1 || vs[0].Quote != "TODO one" {
		t.Fatalf("%+v", vs)
	}
	// the live hints lint a section while it is typed
	s := Load(writeRules(t, map[string]string{"r.yaml": "- id: todo\n  target: sections\n  regex_forbid: 'TODO \\w+'\n  exclude: code\n"}))
	hs := s.RunSection(d, config.Default(), "Description", "TODO one\r\n\r\n```\r\nTODO two")
	if len(hs) != 1 || hs[0].Quote != "TODO one" {
		t.Fatalf("hints %+v", hs)
	}
}

// A pattern the text must match reads a part that is only code as an empty
// part: skipped, and a hit with require_nonempty.
func TestExcludeCodeRequire(t *testing.T) {
	const rule = "- id: need\n  target: sections\n  regex_require: 'Impact'\n  exclude: code\n"
	for body, hits := range map[string]int{
		"```\nImpact\n```":            0, // only code: an empty part
		"`Impact`":                    0,
		"Text.\n\n```\nImpact\n```":   1, // the word is in code only
		"Impact.\n\n```\nImpact\n```": 0,
	} {
		if vs := run(t, rule, codeDoc(body)); len(vs) != hits {
			t.Errorf("%q: %+v", body, vs)
		}
	}
	if vs := run(t, rule+"  require_nonempty: true\n", codeDoc("```\nImpact\n```")); len(vs) != 1 {
		t.Fatalf("only code with require_nonempty: %+v", vs)
	}
}

// The key is a pattern rule's and has one value: anything else is a rule
// that does not load, never a key that is ignored.
func TestExcludeInvalid(t *testing.T) {
	for name, y := range map[string]string{
		"another value": "- id: a\n  regex_forbid: 'x'\n  exclude: tables\n",
		"a check":       "- id: a\n  check: not-empty\n  exclude: code\n",
		"a script":      "- id: a\n  script: a.sh\n  exclude: code\n",
		"an ai rule":    "- id: a\n  ai: Be short.\n  exclude: code\n",
	} {
		s := Load(writeRules(t, map[string]string{"r.yaml": y}))
		if len(s.Rules) != 0 || len(s.Problems) != 1 || !strings.Contains(s.Problems[0].Message, "exclude") {
			t.Errorf("%s: rules %+v problems %+v", name, s.Rules, s.Problems)
		}
	}
}

// The key is kept when a rule is written back to its file (the editor's
// save and the on/off switch do that), and a rule without it gets none.
func TestExcludeWrittenBack(t *testing.T) {
	src := "- id: pw\n  regex_forbid: password\n  exclude: code\n- id: other\n  regex_forbid: x\n"
	rs, ps := Parse("r.yaml", []byte(src))
	if len(ps) != 0 || len(rs) != 2 {
		t.Fatalf("%+v %+v", rs, ps)
	}
	off := false
	for i := range rs {
		rs[i].Enabled = &off
		b, err := SetRule([]byte(src), rs[i].ID, &rs[i])
		if err != nil {
			t.Fatal(err)
		}
		src = string(b)
	}
	if strings.Count(src, "exclude: code") != 1 {
		t.Fatalf("file:\n%s", src)
	}
	back, ps := Parse("r.yaml", []byte(src))
	if len(ps) != 0 || back[0].Exclude != "code" || back[1].Exclude != "" {
		t.Fatalf("%+v %+v", back, ps)
	}
}

// One run reads a section's code once, however many rules have the key.
func TestExcludeCodeParsedOncePerRun(t *testing.T) {
	var y strings.Builder
	for _, id := range []string{"a", "b", "c", "d"} {
		y.WriteString("- id: " + id + "\n  target: sections\n  regex_forbid: 'password'\n  exclude: code\n")
	}
	s := Load(writeRules(t, map[string]string{"r.yaml": y.String()}))
	n := 0
	blankHook = func() { n++ }
	defer func() { blankHook = nil }()
	if vs := s.Run(context.Background(), codeDoc(codeBody), config.Default(), Fast, nil); len(vs) != 4 {
		t.Fatalf("%+v", vs)
	}
	if n != 1 {
		t.Fatalf("the section was read %d times", n)
	}
}
