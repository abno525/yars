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
}

var headingRe = regexp.MustCompile(`^## (.+)$`)

func Parse(b []byte) (*Finding, error) {
	s := strings.ReplaceAll(string(b), "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") {
		return nil, errors.New("finding: missing front matter")
	}
	end := strings.Index(s[4:], "\n---\n")
	if end < 0 {
		return nil, errors.New("finding: unterminated front matter")
	}
	f := &Finding{}
	if err := yaml.Unmarshal([]byte(s[4:4+end+1]), &f.Meta); err != nil {
		return nil, err
	}
	rest := s[4+end+5:]

	var cur *Section
	var buf strings.Builder
	inFence := false
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
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
		}
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
	var out bytes.Buffer
	out.WriteString("---\n")
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(4)
	_ = enc.Encode(&f.Meta)
	_ = enc.Close()
	out.WriteString("---\n")
	out.WriteString(f.Preamble)
	for _, s := range f.Sections {
		out.WriteString("## " + s.Name + "\n")
		out.WriteString(s.Body)
	}
	return out.Bytes()
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
