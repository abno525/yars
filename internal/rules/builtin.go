package rules

import (
	"bytes"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/cvss"
)

func (r Rule) builtin(d Doc, cfg config.Config) []Violation {
	var vs []Violation
	add := func(target, detail, q string) {
		msg := detail
		if r.Message != "" {
			msg = r.Message + " (" + detail + ")"
		}
		vs = append(vs, r.v(target, msg, q))
	}
	switch r.Check {
	case "table-cells-no-backticks":
		for _, p := range parts(d, r.Target) {
			switch p.Kind {
			case "details":
				if strings.Contains(p.Text, "`") {
					add(p.Target, "backticks are not allowed in table fields", p.Text)
				}
			case "section":
				for _, line := range tableRows(p.Text) {
					if strings.Contains(line, "`") {
						add(p.Target, "backticks are not allowed in table cells", line)
					}
				}
			}
		}
	case "cvss-explained":
		v, err := cvss.Parse(d.CVSS)
		if err != nil {
			return nil
		}
		for _, mt := range cvss.Metrics {
			if cfg.NonStandard(mt.Key, v[mt.Key]) && strings.TrimSpace(d.CVSSReasons[mt.Key]) == "" {
				add("cvss", "non-standard CVSS value for "+mt.Name+" needs an explanation", mt.Key+":"+v[mt.Key])
			}
		}
	case "not-empty":
		for _, p := range parts(d, r.Target) {
			if strings.TrimSpace(p.Text) == "" {
				add(p.Target, p.Target+" is empty", "")
			}
		}
	}
	return vs
}

// tableMD reads tables as the page's renderer does (GFM tables).
var tableMD = goldmark.New(goldmark.WithExtensions(extension.Table))

// blanked is a section's text with its code blanked: every byte of a fenced
// block (its language word too), an indented block or a code span is a
// space, line ends stay. code marks those bytes, the line ends inside them
// included.
type blanked struct {
	text string
	code []bool
}

// inCode reports whether the match from..to lies in code alone: the blanks
// that stand for code are no text a pattern can hit.
func (b blanked) inCode(from, to int) bool {
	if from == to {
		return from < len(b.code) && b.code[from]
	}
	for i := from; i < to; i++ {
		if !b.code[i] {
			return false
		}
	}
	return true
}

// codeMemo keeps the blanked text of the sections of one run, by text.
type codeMemo map[string]blanked

// blankHook is called for each text that is parsed (tests count them).
var blankHook func()

func (m codeMemo) of(body string) blanked {
	if b, ok := m[body]; ok {
		return b
	}
	b := blankCode(body)
	if m != nil {
		m[body] = b
	}
	return b
}

// blankCode finds the code of body as the page's renderer does (an unclosed
// fence makes the rest of the text code) and blanks it.
func blankCode(body string) blanked {
	if blankHook != nil {
		blankHook()
	}
	src := []byte(body)
	out := []byte(body)
	code := make([]bool, len(src))
	mark := func(from, to int) {
		for i := max(from, 0); i < to && i < len(src); i++ {
			code[i] = true
			if src[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	lines := func(ls *text.Segments) {
		for i := range ls.Len() {
			s := ls.At(i)
			mark(s.Start, s.Stop)
		}
	}
	ast.Walk(tableMD.Parser().Parse(text.NewReader(src)), func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch c := n.(type) {
		case *ast.FencedCodeBlock:
			if c.Info != nil {
				mark(c.Info.Segment.Start, c.Info.Segment.Stop)
			}
			lines(c.Lines())
			return ast.WalkSkipChildren, nil
		case *ast.CodeBlock:
			lines(c.Lines())
			return ast.WalkSkipChildren, nil
		case *ast.CodeSpan:
			for ch := c.FirstChild(); ch != nil; ch = ch.NextSibling() {
				if t, ok := ch.(*ast.Text); ok {
					mark(t.Segment.Start, t.Segment.Stop)
				}
			}
			return ast.WalkSkipChildren, nil
		}
		return ast.WalkContinue, nil
	})
	return blanked{text: string(out), code: code}
}

// tableRows returns the source lines of the table rows in body, as the
// renderer reads them: no table in a code block, tables in block quotes,
// and a last row written without pipes. A row's line is where its first
// text starts.
func tableRows(body string) []string {
	src := []byte(body)
	var out []string
	ast.Walk(tableMD.Parser().Parse(text.NewReader(src)), func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering || (n.Kind() != east.KindTableRow && n.Kind() != east.KindTableHeader) {
			return ast.WalkContinue, nil
		}
		start := -1
		ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
			if t, ok := c.(*ast.Text); ok && entering && start < 0 {
				start = t.Segment.Start
			}
			return ast.WalkContinue, nil
		})
		if start >= 0 {
			from, to := bytes.LastIndexByte(src[:start], '\n')+1, len(src)
			if i := bytes.IndexByte(src[start:], '\n'); i >= 0 {
				to = start + i
			}
			out = append(out, string(src[from:to]))
		}
		return ast.WalkSkipChildren, nil
	})
	return out
}
