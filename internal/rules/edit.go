package rules

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"gopkg.in/yaml.v3"
)

// Builtin is a built-in check a rule can name.
type Builtin struct{ ID, Name string }

// Builtins lists the built-in checks in the order the editor shows them.
var Builtins = []Builtin{
	{"table-cells-no-backticks", "No backticks in tables"},
	{"cvss-explained", "CVSS reasons filled in"},
	{"not-empty", "Not empty"},
}

// KindName is the rule's kind: pattern, builtin, script or ai.
func (r Rule) KindName() string {
	switch {
	case r.RegexForbid != "" || r.RegexRequire != "":
		return "pattern"
	case r.Check != "":
		return "builtin"
	case r.Script != "":
		return "script"
	case r.AI != "":
		return "ai"
	}
	return ""
}

// On reports whether the rule is enabled (the default).
func (r Rule) On() bool { return r.Enabled == nil || *r.Enabled }

// Validate checks the rule as Load would (id, level, one kind, a valid
// regex, a known check and target).
func (r Rule) Validate() error { return r.prepare() }

// fileRule is a rule as written to a file: empty fields left out.
type fileRule struct {
	ID              string `yaml:"id"`
	Level           string `yaml:"level,omitempty"`
	Message         string `yaml:"message,omitempty"`
	Target          string `yaml:"target,omitempty"`
	RegexForbid     string `yaml:"regex_forbid,omitempty"`
	RegexRequire    string `yaml:"regex_require,omitempty"`
	Check           string `yaml:"check,omitempty"`
	Script          string `yaml:"script,omitempty"`
	AI              string `yaml:"ai,omitempty"`
	RequireNonempty bool   `yaml:"require_nonempty,omitempty"`
	Enabled         *bool  `yaml:"enabled,omitempty"`
}

func fileOf(r Rule) fileRule {
	f := fileRule{ID: r.ID, Level: r.Level, Message: r.Message, Target: r.Target, RegexForbid: r.RegexForbid,
		RegexRequire: r.RegexRequire, Check: r.Check, Script: r.Script, AI: r.AI, RequireNonempty: r.RequireNonempty}
	if !r.On() {
		off := false
		f.Enabled = &off
	}
	return f
}

// SetRule edits the content b of a rule file: the rule with id is replaced
// by r in place, r is appended when id is "" or absent, and the rule is
// removed when r is nil. Other rules and comments are kept. A file left
// without rules comes back nil.
func SetRule(b []byte, id string, r *Rule) ([]byte, error) {
	var doc yaml.Node
	if len(bytes.TrimSpace(b)) > 0 {
		if err := yaml.Unmarshal(b, &doc); err != nil {
			return nil, err
		}
	}
	var seq *yaml.Node
	switch {
	case doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 && doc.Content[0].Kind == yaml.SequenceNode:
		seq = doc.Content[0]
	case doc.Kind == 0 || (doc.Kind == yaml.DocumentNode && len(doc.Content) == 0):
		seq = &yaml.Node{Kind: yaml.SequenceNode}
		doc = yaml.Node{Kind: yaml.DocumentNode, HeadComment: doc.HeadComment, Content: []*yaml.Node{seq}}
	default:
		return nil, errors.New("the rule file is not a list of rules")
	}
	at := -1
	for i, n := range seq.Content {
		if id != "" && n.Kind == yaml.MappingNode {
			for j := 0; j+1 < len(n.Content); j += 2 {
				if n.Content[j].Value == "id" && n.Content[j+1].Value == id {
					at = i
				}
			}
		}
	}
	if r == nil {
		if at < 0 {
			return nil, fmt.Errorf("rule %s not found", id)
		}
		seq.Content = slices.Delete(seq.Content, at, at+1)
	} else {
		var n yaml.Node
		if err := n.Encode(fileOf(*r)); err != nil {
			return nil, err
		}
		if at >= 0 {
			n.HeadComment, n.LineComment, n.FootComment = seq.Content[at].HeadComment, seq.Content[at].LineComment, seq.Content[at].FootComment
			seq.Content[at] = &n
		} else {
			seq.Content = append(seq.Content, &n)
		}
	}
	if len(seq.Content) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Rule finds a loaded rule by id.
func (e *Engine) Rule(id string) (Rule, bool) {
	for _, r := range e.Rules().Rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// RunRule runs one rule (even a disabled one, scripts and AI included) on
// a finding document within the time budget, and stores nothing.
func (e *Engine) RunRule(ctx context.Context, r Rule, d Doc) []Violation {
	r.Enabled = nil
	if err := r.prepare(); err != nil {
		return []Violation{{Rule: r.ID, Level: "error", Target: "rules", Message: "rule invalid: " + err.Error()}}
	}
	if e.Budget > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.Budget)
		defer cancel()
	}
	set := &Set{Dir: e.Dir, Rules: []Rule{r}}
	return set.Run(ctx, d, e.conf(), All, e.Runner)
}
