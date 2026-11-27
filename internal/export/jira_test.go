package export

import (
	"context"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
)

// Finding text reaches Jira as text: a brace outside a code block is
// escaped (Jira reads {name} as a macro), a code block names only a language
// Jira knows, a block whose text holds {code} cannot end itself, and a
// Markdown table becomes a Jira table.
func TestMdToJira(t *testing.T) {
	for name, c := range map[string]struct{ md, want string }{
		"braces in prose":           {"a {color:red}x{color} b", `a \{color:red\}x\{color\} b`},
		"braces in inline code":     {"use `a{b}` here", `use {{a\{b\}}} here`},
		"braces in a heading":       {"## Sub {x}", `h3. Sub \{x\}`},
		"braces in a list":          {"- one {html}\n  - two", "* one \\{html\\}\n** two"},
		"a backslash before":        {`a \{b}`, "a \\\u200b\\{b\\}"},
		"bold and a link":           {"**b** [t](https://x.test/a)", "*b* [t|https://x.test/a]"},
		"unknown language":          {"```http\nGET / HTTP/1.1\n```", "{code}\nGET / HTTP/1.1\n{code}"},
		"mapped language":           {"```js\nx({a: 1})\n```", "{code:javascript}\nx({a: 1})\n{code}"},
		"language in capitals":      {"```Python title\nx\n```", "{code:python}\nx\n{code}"},
		"macro as a language":       {"```x}{panel:title=y\nbody\n```", "{code}\nbody\n{code}"},
		"language then a macro":     {"```sql}{html}\nbody\n```", "{code}\nbody\n{code}"},
		"{code} in the block":       {"```\nline\n{code}\n{panel}evil{panel}\n```\nafter", "{noformat}\nline\n{code}\n{panel}evil{panel}\n{noformat}\nafter"},
		"{CODE:x} in the block":     {"```sh\n{CODE:java}\n```", "{noformat}\n{CODE:java}\n{noformat}"},
		"both in the block":         {"```\n{code}\n{noformat}\n```", "{noformat}\n{code}\n{\u200bnoformat}\n{noformat}"},
		"a fence of the other kind": {"~~~\n```\n{panel}\n~~~\nafter {x}", "{code}\n```\n{panel}\n{code}\nafter \\{x\\}"},
		"a shorter fence":           {"````\n```\n{x}\n````", "{code}\n```\n{x}\n{code}"},
		"an unclosed block":         {"```\n{x}", "{code}\n{x}\n{code}"},
		"a table": {"before\n\n| A | B {x} |\n|---|:--:|\n| 1 | x\\|y |\n| `{z}` |  |\n\nafter",
			"before\n\n||A||B \\{x\\}||\n|1|x\\|y|\n|{{\\{z\\}}}| |\n\nafter"},
		"a table without outer pipes": {"A | B\n-- | --\n1 | 2", "||A||B||\n|1|2|"},
		"a table without rows":        {"| A | B |\n|---|---|\ntext", "||A||B||\n|text| |"},
		"a table in a code block":     {"```\n|a|b|\n|---|---|\n```", "{code}\n|a|b|\n|---|---|\n{code}"},
		"no table":                    {"a | b\nc | d", "a | b\nc | d"},
	} {
		if got := mdToJira(c.md); got != c.want {
			t.Errorf("%s:\n%q\ngot\n%q\nwant\n%q", name, c.md, got, c.want)
		}
	}
}

// The summary table, the CVSS explanations and a section's name are
// escaped as the text is.
func TestJiraTextEscapes(t *testing.T) {
	f, err := finding.Parse([]byte("---\nid: F-009\ntitle: T\nseverity: high\ncvss: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\ncvss_reasons:\n  AV: \"{html}x|y\"\ndetails:\n  Location: \"{panel}a|b\"\n---\n\n## Description\n\nText {html}.\n\n## Notes {x}\n\nMore.\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := jiraText(f, Input{Cfg: config.Default()})
	for _, want := range []string{`||Location|\{panel\}a\|b|`, `|\{html\}x\|y|`, "h2. Description\n\nText \\{html\\}.", `h2. Notes \{x\}`} {
		if !strings.Contains(got, want) {
			t.Errorf("lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(strings.ReplaceAll(got, `\{`, ""), "{") {
		t.Errorf("a brace is left as it was:\n%s", got)
	}
}

// The priority a severity is sent with comes from the destination's file:
// a named severity takes the name written (none when it is empty), one the
// file does not name keeps Jira's default name, and a severity without
// either sends no priority.
func TestJiraPriorities(t *testing.T) {
	sent := func(set map[string]string) (any, bool) {
		t.Helper()
		r, e, j, _ := jiraSetup(t)
		e.Jira.Priorities = set
		if _, err := r.Run(context.Background(), e, oneFinding(t)); err != nil { // F-001, high
			t.Fatal(err)
		}
		f := j.bodies[len(j.bodies)-1]["fields"].(map[string]any)
		p, ok := f["priority"].(map[string]any)
		return p["name"], ok
	}
	if p, _ := sent(nil); p != "High" {
		t.Errorf("without the key: %v", p)
	}
	if p, _ := sent(map[string]string{"high": "P2"}); p != "P2" {
		t.Errorf("high named P2: %v", p)
	}
	if p, _ := sent(map[string]string{"critical": "P1"}); p != "High" {
		t.Errorf("a file that names another severity: %v", p)
	}
	if p, ok := sent(map[string]string{"high": ""}); ok {
		t.Errorf("an empty name still sends a priority: %v", p)
	}
	// the key is read from the file
	e, err := Parse("j.yaml", []byte("type: jira\njira:\n  base_url: https://j.example.com\n  project: SEC\n  user_env: JIRA_USER\n  token_env: JIRA_TOKEN\n  priorities:\n    critical: Blocker\n    info: \"\"\n"))
	if err != nil || e.Jira.Priorities["critical"] != "Blocker" || e.Jira.priority("critical") != "Blocker" || e.Jira.priority("info") != "" || e.Jira.priority("low") != "Low" || e.Jira.priority("urgent") != "" {
		t.Fatalf("%+v %v", e.Jira, err)
	}
	if _, err := Parse("j.yaml", []byte("type: jira\njira:\n  base_url: https://j.example.com\n  project: SEC\n  user_env: JIRA_USER\n  token_env: JIRA_TOKEN\n  priorities:\n    high: \"P2\\nx\"\n")); err == nil {
		t.Fatal("a priority name with a line break was taken")
	}
}
