package render

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	east "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"
)

// checkMD parses and renders as New does, for SameOutside.
var checkMD = goldmark.New(goldmark.WithExtensions(extension.GFM),
	goldmark.WithRendererOptions(renderer.WithNodeRenderers(util.Prioritized(codeRenderer{}, 100))))

// SameOutside reports whether nw renders like old everywhere outside one
// changed stretch: oldAt and newAt are its byte ranges in old and in nw
// (M31: the paragraph a fix may change). It holds when the two have the
// same link definitions (one in the stretch would serve links anywhere), no
// block runs into or out of the stretch in either (raw HTML, a code fence),
// and the blocks outside it render the same, in the same order and inside
// the same containers (a list stays tight or loose).
func SameOutside(old, nw string, oldAt, newAt [2]int) bool {
	ob, orefs, ok := outside([]byte(old), oldAt)
	if !ok {
		return false
	}
	nb, nrefs, ok := outside([]byte(nw), newAt)
	return ok && orefs == nrefs && slices.Equal(ob, nb)
}

// outside lists the blocks of src outside the stretch at, each rendered with
// its containers, and src's link definitions; false when a block crosses
// the stretch's edge.
func outside(src []byte, at [2]int) ([]string, string, bool) {
	pc := parser.NewContext()
	doc := checkMD.Parser().Parse(text.NewReader(src), parser.WithContext(pc))
	var refs []string
	for _, r := range pc.References() {
		refs = append(refs, fmt.Sprintf("%s\x00%s\x00%s", r.Label(), r.Destination(), r.Title()))
	}
	slices.Sort(refs)
	var out []string
	ok := true
	var walk func(n ast.Node, path string)
	walk = func(n ast.Node, path string) {
		for c := n.FirstChild(); c != nil && ok; c = c.NextSibling() {
			if c.Type() != ast.TypeBlock {
				continue
			}
			if container(c) {
				walk(c, path+"/"+label(c))
				continue
			}
			if lo, hi, placed := extent(c); placed && hi > at[0] && lo < at[1] {
				if lo >= at[0] && hi <= at[1] {
					continue // the stretch's own
				}
				ok = false
				return
			}
			var buf bytes.Buffer
			if err := checkMD.Renderer().Render(&buf, src, c); err != nil {
				ok = false
				return
			}
			out = append(out, path+"\x00"+buf.String())
		}
	}
	walk(doc, "")
	return out, strings.Join(refs, "\x01"), ok
}

// container: a block holding blocks (a list, its items, a quote); a table
// is one block.
func container(n ast.Node) bool {
	if n.Kind() == east.KindTable {
		return false
	}
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		if c.Type() == ast.TypeBlock {
			return true
		}
	}
	return false
}

// label names a container with what changes how its blocks render: a list
// its kind, start and tightness, an item its place in the list (two lists
// made one, or one split, renumber the items after the change).
func label(n ast.Node) string {
	switch l := n.(type) {
	case *ast.List:
		return fmt.Sprintf("%s(%c,%d,%v)", n.Kind(), l.Marker, l.Start, l.IsTight)
	case *ast.ListItem:
		k := 0
		for p := n.PreviousSibling(); p != nil; p = p.PreviousSibling() {
			k++
		}
		return fmt.Sprintf("%s#%d", n.Kind(), k)
	}
	return n.Kind().String()
}

// extent is the byte range n's text comes from (its lines, its text's, an
// HTML block's closing line); placed is false for a block with no text (a
// thematic break).
func extent(n ast.Node) (lo, hi int, placed bool) {
	lo, hi = -1, -1
	add := func(s text.Segment) {
		if s.Stop < s.Start {
			return
		}
		if lo < 0 || s.Start < lo {
			lo = s.Start
		}
		if s.Stop > hi {
			hi = s.Stop
		}
	}
	ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		if c.Type() == ast.TypeBlock {
			lines := c.Lines()
			for i := 0; i < lines.Len(); i++ {
				add(lines.At(i))
			}
			if h, ok := c.(*ast.HTMLBlock); ok && h.HasClosure() {
				add(h.ClosureLine)
			}
		}
		if t, ok := c.(*ast.Text); ok {
			add(t.Segment)
		}
		return ast.WalkContinue, nil
	})
	return lo, hi, lo >= 0
}
