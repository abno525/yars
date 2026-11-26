package config

import (
	"bytes"
	"errors"

	"gopkg.in/yaml.v3"

	"github.com/abno525/yars/internal/cvss"
)

// SetStructure writes c's report structure (sections, details rows,
// severities, report sections, CVSS version and standard) into the YAML of
// a config.yaml, keeping every other key and the comments. A metric without
// a standard is written as "-" so the built-in default doesn't come back.
func SetStructure(raw []byte, c Config) ([]byte, error) {
	var doc yaml.Node
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("config: the file must be a mapping")
	}
	list := func(v []string) *yaml.Node {
		n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, s := range v {
			n.Content = append(n.Content, str(s))
		}
		return n
	}
	setKey(root, "sections", list(c.Sections))
	setKey(root, "details_rows", list(c.DetailsRows))
	setKey(root, "severities", list(c.Severities))
	setKey(root, "report_sections", list(c.ReportSections))
	cv := getKey(root, "cvss")
	if cv == nil || cv.Kind != yaml.MappingNode {
		cv = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		setKey(root, "cvss", cv)
	}
	ver := str(c.CVSS.Version)
	ver.Style = yaml.DoubleQuotedStyle
	setKey(cv, "version", ver)
	std := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, m := range cvss.Metrics {
		v, ok := c.CVSS.Standard[m.Key]
		if !ok || v == "" {
			v = "-"
		}
		std.Content = append(std.Content, str(m.Key), str(v))
	}
	setKey(cv, "standard", std)
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(4)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	enc.Close()
	return out.Bytes(), nil
}

func str(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }

func getKey(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// setKey replaces key's value in mapping m (keeping the key's comments) or
// appends the key.
func setKey(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			old := m.Content[i+1]
			v.LineComment = old.LineComment
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, str(key), v)
}
