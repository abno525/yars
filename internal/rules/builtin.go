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
