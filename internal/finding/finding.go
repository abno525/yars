// Package finding parses and serializes finding.md files:
// YAML front matter followed by "## " sections.
package finding

import (
	"bytes"
	"errors"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Retest struct {
	Source string `yaml:"source"`
	Result string `yaml:"result"`
}

type Meta struct {
	ID        string         `yaml:"id"`
	Title     string         `yaml:"title"`
	Status    string         `yaml:"status"`
	Severity  string         `yaml:"severity"`
	CVSS      string         `yaml:"cvss"`
	Author    string         `yaml:"author"`
	Reviewers []string       `yaml:"reviewers"`
	Retest    *Retest        `yaml:"retest,omitempty"`
	Extra     map[string]any `yaml:",inline"`
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
