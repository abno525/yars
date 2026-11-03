// Package finding parses and serializes finding.md files:
// YAML front matter followed by "## " sections.
package finding

import (
	"bytes"
	"errors"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type Retest struct {
	Source string `yaml:"source"`
	Result string `yaml:"result"`
}

type Meta struct {
	ID        string   `yaml:"id"`
	Title     string   `yaml:"title"`
	Status    string   `yaml:"status"`
	Severity  string   `yaml:"severity"`
	CVSS      string   `yaml:"cvss"`
	Author    string   `yaml:"author"`
	Reviewers []string `yaml:"reviewers"`
	Retest    *Retest  `yaml:"retest,omitempty"`
	// CVSSReasons explains non-standard CVSS metric values, keyed by metric (e.g. "AC").
	CVSSReasons map[string]string `yaml:"cvss_reasons,omitempty"`
	// Details holds the details table, keyed by configured row name.
	Details map[string]string `yaml:"details,omitempty"`
	Extra   map[string]any    `yaml:",inline"`
}

// SetMeta sets (or, with a nil value, deletes) one top-level front-matter key.
// Only the lines of that key are rewritten (spliced into the raw text), so
// every other line — comments, blank lines, indentation, quoting — stays
// byte-identical. A new key is appended at the end. value may be a
// *yaml.Node or any encodable Go value.
func (f *Finding) SetMeta(key string, value any) error {
	src := f.rawMeta
	if src == "" || encodeMeta(&f.Meta) != f.metaSnap {
		src = encodeMeta(&f.Meta)
	}
	if src != "" && !strings.HasSuffix(src, "\n") {
		src += "\n"
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		return err
	}
	var m *yaml.Node
	if doc.Kind != 0 && len(doc.Content) > 0 {
		m = doc.Content[0]
		if m.Kind != yaml.MappingNode || m.Style&yaml.FlowStyle != 0 {
			return errors.New("finding: front matter must be a block mapping")
		}
	}
	var vn *yaml.Node
	if value != nil {
		if n, ok := value.(*yaml.Node); ok {
			vn = n
		} else {
			vn = &yaml.Node{}
			if err := vn.Encode(value); err != nil {
				return err
			}
		}
	}
	// Locate the key's line range [start, end): its own line plus following
	// lines that are indented, blank, or zero-indent sequence items.
	lines := strings.SplitAfter(src, "\n")
	start, end := -1, -1
	var old *yaml.Node
	for i := 0; m != nil && i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Value != key {
			continue
		}
		if k.Column != 1 {
			return errors.New("finding: top-level front matter keys must start at column 1")
		}
		old, start = m.Content[i+1], k.Line-1
		end = start + 1
		for end < len(lines) && lines[end] != "" && strings.ContainsRune(" \t-\n", rune(lines[end][0])) {
			end++
		}
		for end > start+1 && strings.TrimSpace(lines[end-1]) == "" {
			end--
		}
		break
	}
	if start < 0 && vn == nil {
		return nil // deleting an absent key
	}
	snippet := ""
	if vn != nil {
		if old != nil && vn.LineComment == "" {
			vn.LineComment = old.LineComment
		}
		one := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map",
			Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, vn}}
		var out bytes.Buffer
		enc := yaml.NewEncoder(&out)
		enc.SetIndent(4)
		if err := enc.Encode(one); err != nil {
			return err
		}
		enc.Close()
		snippet = out.String()
	}
	var b strings.Builder
	if start >= 0 {
		b.WriteString(strings.Join(lines[:start], ""))
		b.WriteString(snippet)
		b.WriteString(strings.Join(lines[end:], ""))
	} else {
		b.WriteString(src)
		b.WriteString(snippet)
	}
	var meta Meta
	if err := yaml.Unmarshal([]byte(b.String()), &meta); err != nil {
		return err
	}
	f.Meta, f.rawMeta = meta, b.String()
	f.metaSnap = encodeMeta(&f.Meta)
	return nil
}

// OrderedMap builds a string mapping node with keys in the given order
// (absent keys skipped), followed by remaining keys of m sorted. Multi-line
// values use literal block style.
func OrderedMap(keys []string, m map[string]string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	add := func(k string) {
		v := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: m[k]}
		if strings.Contains(m[k], "\n") {
			v.Style = yaml.LiteralStyle
		}
		n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, v)
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if _, ok := m[k]; ok && !seen[k] {
			add(k)
			seen[k] = true
		}
	}
	var rest []string
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		add(k)
	}
	return n
}

// Section is a "## Name" block; Body is everything after the heading line
// up to the next heading, verbatim.
type Section struct {
	Name string
	Body string
}

type Finding struct {
	Meta     Meta
	Preamble string
	Sections []Section

	rawMeta  string // front matter text exactly as read (LF-normalized)
	metaSnap string // Meta encoding at parse time, to detect deliberate changes
	crlf     bool   // file used CRLF line endings
}

var headingRe = regexp.MustCompile(`^## (.+)$`)

// fence tracks CommonMark fenced code blocks line by line.
type fence struct {
	char byte
	n    int
}

var fenceRe = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})(.*)$")

// step consumes one line (without newline) and reports whether the line is
// inside (or delimits) a fenced code block.
func (f *fence) step(line string) bool {
	m := fenceRe.FindStringSubmatch(line)
	if f.n == 0 {
		if m == nil || (m[1][0] == '`' && strings.Contains(m[2], "`")) {
			return false
		}
		f.char, f.n = m[1][0], len(m[1])
		return true
	}
	if m != nil && m[1][0] == f.char && len(m[1]) >= f.n && strings.TrimSpace(m[2]) == "" {
		f.n = 0
	}
	return true
}

// ValidateBody rejects section bodies that would corrupt the file structure:
// a top-level "## " heading (would start a new section) or an unclosed fence
// (would swallow following sections).
func ValidateBody(body string) error {
	var fc fence
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if fc.step(line) {
			continue
		}
		if headingRe.MatchString(line) {
			return errors.New("level-2 headings (## ) are reserved for sections; use ### instead")
		}
	}
	if fc.n != 0 {
		return errors.New("unclosed code fence")
	}
	return nil
}

func encodeMeta(m *Meta) string {
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(4)
	_ = enc.Encode(m)
	_ = enc.Close()
	return out.String()
}

func Parse(b []byte) (*Finding, error) {
	s := string(b)
	f := &Finding{crlf: strings.Contains(s, "\r\n")}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") {
		return nil, errors.New("finding: missing front matter")
	}
	end := strings.Index(s[4:], "\n---\n")
	if end < 0 {
		return nil, errors.New("finding: unterminated front matter")
	}
	f.rawMeta = s[4 : 4+end+1]
	if err := yaml.Unmarshal([]byte(f.rawMeta), &f.Meta); err != nil {
		return nil, err
	}
	f.metaSnap = encodeMeta(&f.Meta)
	rest := s[4+end+5:]

	var cur *Section
	var buf strings.Builder
	var fc fence
	flush := func() {
		if cur == nil {
			f.Preamble = buf.String()
		} else {
			cur.Body = buf.String()
			f.Sections = append(f.Sections, *cur)
		}
		buf.Reset()
	}
	for _, line := range strings.SplitAfter(rest, "\n") {
		if line == "" {
			continue
		}
		trimmed := strings.TrimSuffix(line, "\n")
		inFence := fc.step(trimmed)
		if m := headingRe.FindStringSubmatch(trimmed); m != nil && !inFence {
			flush()
			cur = &Section{Name: strings.TrimSpace(m[1])}
			continue
		}
		buf.WriteString(line)
	}
	flush()
	return f, nil
}

func (f *Finding) Bytes() []byte {
	var out strings.Builder
	out.WriteString("---\n")
	// Keep the front matter byte-for-byte (comments, order, style) unless
	// Meta was deliberately changed since parsing.
	if enc := encodeMeta(&f.Meta); f.rawMeta != "" && enc == f.metaSnap {
		out.WriteString(f.rawMeta)
	} else {
		out.WriteString(enc)
	}
	out.WriteString("---\n")
	out.WriteString(f.Preamble)
	for _, s := range f.Sections {
		out.WriteString("## " + s.Name + "\n")
		out.WriteString(s.Body)
	}
	if f.crlf {
		return []byte(strings.ReplaceAll(out.String(), "\n", "\r\n"))
	}
	return []byte(out.String())
}

func (f *Finding) Section(name string) (string, bool) {
	for _, s := range f.Sections {
		if s.Name == name {
			return s.Body, true
		}
	}
	return "", false
}

// SetSection replaces the body of the named section (normalized to a blank
// line, the text, and a trailing blank line unless it is last), or appends
// the section if it does not exist.
func (f *Finding) SetSection(name, body string) {
	norm := "\n" + strings.Trim(strings.ReplaceAll(body, "\r\n", "\n"), "\n") + "\n"
	for i := range f.Sections {
		if f.Sections[i].Name == name {
			if i < len(f.Sections)-1 {
				norm += "\n"
			}
			f.Sections[i].Body = norm
			return
		}
	}
	if n := len(f.Sections); n > 0 && !strings.HasSuffix(f.Sections[n-1].Body, "\n\n") {
		f.Sections[n-1].Body = strings.TrimRight(f.Sections[n-1].Body, "\n") + "\n\n"
	}
	f.Sections = append(f.Sections, Section{Name: name, Body: norm})
}

// New returns an empty draft finding with the given sections.
func New(id, title, author string, sections []string) *Finding {
	f := &Finding{
		Meta:     Meta{ID: id, Title: title, Status: "draft", Author: author, Reviewers: []string{}},
		Preamble: "\n",
	}
	for i, name := range sections {
		body := "\n"
		if i < len(sections)-1 {
			body = "\n\n"
		}
		f.Sections = append(f.Sections, Section{Name: name, Body: body})
	}
	return f
}
