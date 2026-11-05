package render

import (
	"html/template"
	"regexp"
	"strings"

	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/util"
)

// httpLangs are the fenced-code info strings shown as HTTP messages.
var httpLangs = map[string]bool{"http": true, "http-request": true, "http-response": true}

var (
	reqLine    = regexp.MustCompile(`^([A-Z][A-Z-]*) (\S+) (HTTP/[0-9.]+)$`)
	statusLine = regexp.MustCompile(`^(HTTP/[0-9.]+) ([1-5][0-9][0-9])(?: (.*))?$`)
	headerLine = regexp.MustCompile("^([!#$%&'*+.^_`|~0-9A-Za-z-]+):[ \\t]?(.*)$")
)

func span(class, text string) string {
	return `<span class="` + class + `">` + template.HTMLEscapeString(text) + `</span>`
}

// startLine marks up a request or status line ("" when it is neither).
func startLine(l string) string {
	if m := reqLine.FindStringSubmatch(l); m != nil {
		return span("h-m", m[1]) + " " + span("h-u", m[2]) + " " + span("h-v", m[3])
	}
	if m := statusLine.FindStringSubmatch(l); m != nil {
		out := span("h-v", m[1]) + " " + span("h-s h-s"+m[2][:1], m[2])
		if m[3] != "" {
			out += " " + span("h-r", m[3])
		}
		return out
	}
	return ""
}

// HighlightHTTP returns HTTP messages (request and/or response lines,
// headers, bodies) as escaped HTML with spans for the start line parts
// (h-m method, h-u target, h-v version, h-s status, h-r reason) and the
// header names (h-k) and values (h-x). A start line after a blank line in a
// body begins the next message.
func HighlightHTTP(src string) string {
	var b strings.Builder
	const (
		start = iota
		headers
		body
	)
	mode, blank := start, true
	for i, l := range strings.Split(strings.TrimSuffix(src, "\n"), "\n") {
		if i > 0 {
			b.WriteByte('\n')
		}
		l = strings.TrimSuffix(l, "\r")
		if mode == body && blank {
			if s := startLine(l); s != "" {
				mode = start
			}
		}
		switch {
		case mode == start && strings.TrimSpace(l) == "":
		case mode == start:
			if s := startLine(l); s != "" {
				b.WriteString(s)
			} else {
				b.WriteString(template.HTMLEscapeString(l))
			}
			mode = headers
		case mode == headers && l == "":
			mode = body
		case mode == headers:
			if m := headerLine.FindStringSubmatch(l); m != nil {
				b.WriteString(span("h-k", m[1]) + ": " + span("h-x", m[2]))
			} else {
				b.WriteString(template.HTMLEscapeString(l))
			}
		default:
			b.WriteString(template.HTMLEscapeString(l))
		}
		blank = strings.TrimSpace(l) == ""
	}
	return b.String()
}

// codeRenderer renders fenced code blocks: HTTP ones highlighted, the
// others as goldmark does.
type codeRenderer struct{}

func (codeRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindFencedCodeBlock, renderFenced)
}

func renderFenced(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	n := node.(*ast.FencedCodeBlock)
	lang := string(n.Language(source))
	if !entering {
		w.WriteString("</code></pre>\n")
		return ast.WalkContinue, nil
	}
	var text strings.Builder
	lines := n.Lines()
	for i := 0; i < lines.Len(); i++ {
		seg := lines.At(i)
		text.Write(seg.Value(source))
	}
	if httpLangs[strings.ToLower(lang)] {
		w.WriteString(`<pre class="http"><code>`)
		w.WriteString(HighlightHTTP(text.String()))
		w.WriteString("\n")
		return ast.WalkContinue, nil
	}
	w.WriteString("<pre><code")
	if lang != "" {
		w.WriteString(` class="language-`)
		w.Write(util.EscapeHTML([]byte(lang)))
		w.WriteString(`"`)
	}
	w.WriteString(">")
	w.Write(util.EscapeHTML([]byte(text.String())))
	return ast.WalkContinue, nil
}
