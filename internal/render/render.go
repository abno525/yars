// Package render turns Markdown into HTML, remembering recent results so a
// section, chat message or preview that did not change is not rendered again.
package render

import (
	"bytes"
	"crypto/sha256"
	"html/template"
	"sync/atomic"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/util"

	"yars/internal/lru"
)

// Size is the default number of rendered texts kept.
const Size = 5000

// Markdown renders GitHub-flavoured Markdown (raw HTML is not passed
// through) and caches the HTML by the SHA-256 of the source. Safe for
// concurrent use.
type Markdown struct {
	md     goldmark.Markdown
	cache  *lru.Cache[[sha256.Size]byte, template.HTML]
	misses atomic.Int64
}

// New returns a renderer that keeps the last size results.
func New(size int) *Markdown {
	md := goldmark.New(goldmark.WithExtensions(extension.GFM),
		goldmark.WithRendererOptions(renderer.WithNodeRenderers(util.Prioritized(codeRenderer{}, 100))))
	return &Markdown{md: md, cache: lru.New[[sha256.Size]byte, template.HTML](size)}
}

// HTML is src rendered; text that fails to render is shown escaped.
func (m *Markdown) HTML(src string) template.HTML {
	key := sha256.Sum256([]byte(src))
	if h, ok := m.cache.Get(key); ok {
		return h
	}
	m.misses.Add(1)
	var buf bytes.Buffer
	h := template.HTML(template.HTMLEscapeString(src))
	if err := m.md.Convert([]byte(src), &buf); err == nil {
		h = template.HTML(buf.String())
	}
	m.cache.Add(key, h)
	return h
}

// Len is the number of cached results.
func (m *Markdown) Len() int { return m.cache.Len() }

// Misses counts the texts that had to be rendered.
func (m *Markdown) Misses() int64 { return m.misses.Load() }
