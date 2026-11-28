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

// Returned records who sent a finding back to draft and why.
type Returned struct {
	By     string `yaml:"by"`
	Reason string `yaml:"reason"`
}

// Meta is the front matter (content) plus the workflow state, which the
// store fills in from the database. State fields are never read from or
// written to the file (yaml:"-").
type Meta struct {
	ID       string `yaml:"id"`
	Title    string `yaml:"title"`
	Severity string `yaml:"severity"`
	CVSS     string `yaml:"cvss"`
	Author   string `yaml:"author"`
	// CVSSReasons explains non-standard CVSS metric values, keyed by metric (e.g. "AC").
	CVSSReasons map[string]string `yaml:"cvss_reasons,omitempty"`
	// Details holds the details table, keyed by configured row name.
	Details map[string]string `yaml:"details,omitempty"`
	Assets  []Asset           `yaml:"assets,omitempty"`
	Extra   map[string]any    `yaml:",inline"`

	// Workflow state (from the database).
	Status    string    `yaml:"-"`
	Reviewers []string  `yaml:"-"`
	ClearedBy []string  `yaml:"-"` // reviewers whose clearance matches the current content
	Returned  *Returned `yaml:"-"` // set when a reviewer sends the finding back to draft
	Withdrawn *Returned `yaml:"-"` // who withdrew the finding and why (status withdrawn)
	Retest    *Retest   `yaml:"-"` // only in retests

	// Where the finding is (from the store, never the file): its engagement's
	// ID, and whether that engagement takes no AI (engagement.yaml's ai: off).
	Engagement string `yaml:"-"`
	NoAI       bool   `yaml:"-"`
}

// Asset is one affected asset: a host and/or URL, an optional port and a
// note.
type Asset struct {
	Host string `yaml:"host,omitempty" json:"host,omitempty"`
	URL  string `yaml:"url,omitempty" json:"url,omitempty"`
	Port string `yaml:"port,omitempty" json:"port,omitempty"`
	Note string `yaml:"note,omitempty" json:"note,omitempty"`
}

// Key identifies an asset regardless of its note and letter case.
func (a Asset) Key() string {
	n := func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	return n(a.Host) + "\x00" + n(a.URL) + "\x00" + n(a.Port)
}

// StateKeys are front-matter keys that used to hold workflow state.
var StateKeys = []string{"cleared_by", "retest", "returned", "reviewers", "status"}

// LegacyState is workflow state found in a file written before it moved to
// the database (read by the migration; rejected on push).
type LegacyState struct {
	Keys      []string  // which state keys the file has, sorted
	Status    string    `yaml:"status"`
	Reviewers []string  `yaml:"reviewers"`
	ClearedBy []string  `yaml:"cleared_by"`
	Returned  *Returned `yaml:"returned"`
	Retest    *Retest   `yaml:"retest"`
}

// Legacy reports workflow-state keys in the file's front matter.
func (f *Finding) Legacy() (LegacyState, bool) {
	var l LegacyState
	for _, k := range StateKeys {
		if _, ok := f.Meta.Extra[k]; ok {
			l.Keys = append(l.Keys, k)
		}
	}
	if len(l.Keys) == 0 {
		return l, false
	}
	keys := l.Keys
	_ = yaml.Unmarshal([]byte(encodeExtra(f.Meta.Extra)), &l)
	l.Keys = keys
	return l, true
}

func encodeExtra(m map[string]any) string {
	b, _ := yaml.Marshal(m)
	return string(b)
}

// SetMeta sets (or, with a nil value, deletes) one top-level front-matter key.
// Only the lines of that key are rewritten (spliced into the raw text), so
// every other line — comments, blank lines, indentation, quoting — stays
// byte-identical. A new key is appended at the end. value may be a
// *yaml.Node or any encodable Go value. The workflow state in Meta is kept.
func (f *Finding) SetMeta(key string, value any) error {
	src := f.rawMeta
	if src == "" || encodeMeta(&f.Meta) != f.metaSnap {
		src = encodeMeta(&f.Meta)
	}
	out, absent, err := spliceKey(src, key, value)
	if err != nil || absent {
		return err
	}
	var meta Meta
	if err := yaml.Unmarshal([]byte(out), &meta); err != nil {
		return err
	}
	// the workflow state is not in the file: it stays as it was
	was := f.Meta
	meta.Status, meta.Reviewers, meta.ClearedBy = was.Status, was.Reviewers, was.ClearedBy
	meta.Returned, meta.Withdrawn, meta.Retest = was.Returned, was.Withdrawn, was.Retest
	meta.Engagement, meta.NoAI = was.Engagement, was.NoAI
	f.Meta, f.rawMeta = meta, out
	f.metaSnap = encodeMeta(&f.Meta)
	return nil
}

// SpliceKey sets (or, with a nil value, deletes) one top-level key of the
// block mapping src (a front matter, an engagement.yaml) as SetMeta does:
// only that key's lines are rewritten, every other byte stays. It refuses a
// mapping written between { } and a top-level key that is indented.
func SpliceKey(src, key string, value any) (string, error) {
	out, _, err := spliceKey(src, key, value)
	return out, err
}

// spliceKey is SpliceKey; absent says the key to delete was not there (out
// is src then).
func spliceKey(src, key string, value any) (out string, absent bool, err error) {
	if src != "" && !strings.HasSuffix(src, "\n") {
		src += "\n"
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		return "", false, err
	}
	var m *yaml.Node
	if doc.Kind != 0 && len(doc.Content) > 0 {
		m = doc.Content[0]
		if m.Kind != yaml.MappingNode || m.Style&yaml.FlowStyle != 0 {
			return "", false, errors.New("finding: front matter must be a block mapping")
		}
	}
	var vn *yaml.Node
	if value != nil {
		if n, ok := value.(*yaml.Node); ok {
			vn = n
		} else {
			vn = &yaml.Node{}
			if err := vn.Encode(value); err != nil {
				return "", false, err
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
			return "", false, errors.New("finding: top-level front matter keys must start at column 1")
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
		return src, true, nil // deleting an absent key
	}
	snippet := ""
	if vn != nil {
		if old != nil && vn.LineComment == "" {
			vn.LineComment = old.LineComment
		}
		one := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map",
			Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, vn}}
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(4)
		if err := enc.Encode(one); err != nil {
			return "", false, err
		}
		enc.Close()
		snippet = buf.String()
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
	return b.String(), false, nil
}

// RawMeta is the front matter text as the file had it (or as SetMeta left
// it); "" for a finding that was not parsed.
func (f *Finding) RawMeta() string { return f.rawMeta }

// MetaProblem says why SetMeta cannot edit the front matter as the file has
// it, in words for the person who wrote it ("" when it can). Parse reads
// more forms than SetMeta's line splice can rewrite: the whole mapping
// between { }, a top-level key that is indented, a value continued on a
// line that starts at the first column, a comment at the first column
// inside a value.
func (f *Finding) MetaProblem() string {
	src := f.rawMeta
	if strings.TrimSpace(src) == "" {
		return ""
	}
	if !strings.HasSuffix(src, "\n") {
		src += "\n"
	}
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil || doc.Kind == 0 || len(doc.Content) == 0 {
		return "" // Parse says what is wrong with it
	}
	m := doc.Content[0]
	if m.Kind != yaml.MappingNode || m.Style&yaml.FlowStyle != 0 {
		return "the front matter must be written one key per line (title: X), not between { }"
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if k := m.Content[i]; k.Column != 1 {
			return "front matter key " + k.Value + " is indented; start every top-level key at the first column"
		}
	}
	// each key's lines as SetMeta finds them: they must reach the next key
	// with nothing but blank lines and comments in between, and not pass it
	lines := strings.SplitAfter(src, "\n")
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		next := len(lines)
		if i+2 < len(m.Content) {
			next = m.Content[i+2].Line - 1
		}
		end := k.Line
		for end < len(lines) && lines[end] != "" && strings.ContainsRune(" \t-\n", rune(lines[end][0])) {
			end++
		}
		bad := end > next
		for j := end; j < next && !bad; j++ {
			t := strings.TrimSpace(lines[j])
			bad = t != "" && !strings.HasPrefix(t, "#")
		}
		if bad {
			return "front matter key " + k.Value + ": indent every line of its value after the first (a list item may start at the first column with -), and keep comments out of it"
		}
	}
	return ""
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
	parsed   bool   // read by Parse: rawMeta is the file's (it may be empty)
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

// FenceMask reports, for each line of body (split on "\n"), whether it is
// inside or delimits a fenced code block.
func FenceMask(body string) []bool {
	lines := strings.Split(body, "\n")
	out := make([]bool, len(lines))
	var fc fence
	for i, l := range lines {
		out[i] = fc.step(strings.TrimSuffix(l, "\r"))
	}
	return out
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

// Parse reads a finding file. It takes what editors write too: a UTF-8 byte
// order mark (not written back), empty front matter, and a closing "---"
// that ends the file without a newline.
//
// The front matter decides the line endings Bytes writes: CRLF when the
// opening "---" line and every line up to and with the closing "---" end
// with CRLF, LF otherwise (front matter with both counts as LF). The text is
// read with LF either way, so a CRLF line in an LF file is written back with
// LF.
func Parse(b []byte) (*Finding, error) {
	s := strings.TrimPrefix(string(b), "\xef\xbb\xbf")
	f := &Finding{crlf: crlfMeta(s), parsed: true}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if !strings.HasPrefix(s, "---\n") {
		return nil, errors.New("finding: missing front matter")
	}
	if strings.HasSuffix(s, "\n---") {
		s += "\n" // a closing "---" at the very end (any other last line stays as it is)
	}
	var rest string
	if strings.HasPrefix(s[4:], "---\n") { // empty front matter
		rest = s[8:]
	} else {
		end := strings.Index(s[4:], "\n---\n")
		if end < 0 {
			return nil, errors.New("finding: unterminated front matter")
		}
		f.rawMeta = s[4 : 4+end+1]
		rest = s[4+end+5:]
	}
	if err := yaml.Unmarshal([]byte(f.rawMeta), &f.Meta); err != nil {
		return nil, err
	}
	f.metaSnap = encodeMeta(&f.Meta)

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

// crlfMeta reports whether the front matter of s is written with CRLF: its
// opening "---" line and every line up to and with the closing "---" (which
// may end the file without a line ending).
func crlfMeta(s string) bool {
	rest, ok := strings.CutPrefix(s, "---\r\n")
	for ok && rest != "" {
		line, after, found := strings.Cut(rest, "\n")
		if !found {
			return line == "---"
		}
		if !strings.HasSuffix(line, "\r") {
			return false
		}
		if line == "---\r" {
			return true
		}
		rest = after
	}
	return false
}

func (f *Finding) Bytes() []byte {
	var out strings.Builder
	out.WriteString("---\n")
	// Keep the front matter byte-for-byte (comments, order, style) unless
	// Meta was deliberately changed since parsing.
	if enc := encodeMeta(&f.Meta); (f.parsed || f.rawMeta != "") && enc == f.metaSnap {
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
		Meta:     Meta{ID: id, Title: title, Status: "draft", Author: author},
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
