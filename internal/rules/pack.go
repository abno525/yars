package rules

import (
	"bytes"
	_ "embed"
	"errors"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed starter.yaml
var starterYAML []byte

// Starter returns the starter rules that ship with the binary, each turned
// off: pattern and built-in rules on the title, the text and the sections,
// so they need no configuration, no script and no AI provider. Admin › Rules
// writes them behind one button; yars init writes none.
func Starter() []Rule {
	rs, _ := Parse("starter.yaml", starterYAML)
	for i := range rs {
		rs[i] = offCopy(rs[i])
	}
	return rs
}

// offCopy is r turned off, without the file it was read from.
func offCopy(r Rule) Rule {
	off := false
	r.Enabled, r.File = &off, ""
	return r
}

// Pack writes rules as one rule file: a YAML list, each rule as the editor
// writes it (a rule that is off keeps enabled: false).
func Pack(rs []Rule) ([]byte, error) {
	list := make([]fileRule, 0, len(rs))
	for _, r := range rs {
		list = append(list, fileOf(r))
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(list); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ParsePack reads a pack: one YAML list of rules, as a rule file is. It is
// other people's file, so one problem refuses all of it: content that is no
// list, a key the rules do not have, a rule that does not load (no id, a
// level, none or several kinds, a pattern that does not compile, an unknown
// check, target or exclude) and an id used twice. The error says which, in
// the words the rules page uses. The rules come back as written (on or off),
// without a file.
func ParsePack(b []byte) ([]Rule, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, errors.New("the file is not YAML")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.SequenceNode {
		return nil, errors.New("the file is not a list of rules")
	}
	for _, n := range doc.Content[0].Content {
		if n.Kind != yaml.MappingNode {
			return nil, errors.New("the file is not a list of rules")
		}
	}
	const file = "pack"
	rs, problems := Parse(file, b)
	if len(problems) > 0 {
		return nil, errors.New(strings.TrimPrefix(problems[0].Message, "rule invalid ("+file+"): "))
	}
	if len(rs) == 0 {
		return nil, errors.New("the file has no rules")
	}
	for i := range rs {
		rs[i].File = ""
	}
	return rs, nil
}
