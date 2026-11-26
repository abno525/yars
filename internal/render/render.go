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

	"github.com/abno525/yars/internal/lru"
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

// MaxCached is the largest source, in bytes, whose result is kept. A larger
// one is rendered each time: any account can post a body of megabytes to
// the preview, and a section that long is rare.
const MaxCached = 64 << 10

// Budget is the most cached HTML kept, in bytes. The HTML of a list or a
// table is several times its source, so the entry count alone bounds
// nothing.
const Budget = 64 << 20

// New returns a renderer that keeps the last size results, within Budget.
func New(size int) *Markdown { return newBudget(size, Budget) }

func newBudget(size int, budget int64) *Markdown {
	md := goldmark.New(goldmark.WithExtensions(extension.GFM),
		goldmark.WithRendererOptions(renderer.WithNodeRenderers(util.Prioritized(codeRenderer{}, 100))))
	return &Markdown{md: md, cache: lru.NewSized[[sha256.Size]byte](size, budget,
		func(h template.HTML) int64 { return int64(len(h)) })}
}

// HTML is src rendered; text that fails to render is shown escaped.
func (m *Markdown) HTML(src string) template.HTML {
	keep := len(src) <= MaxCached
	var key [sha256.Size]byte
	if keep {
		key = sha256.Sum256([]byte(src))
		if h, ok := m.cache.Get(key); ok {
			return h
		}
	}
	m.misses.Add(1)
	var buf bytes.Buffer
	h := template.HTML(template.HTMLEscapeString(src))
	if err := m.md.Convert([]byte(src), &buf); err == nil {
		h = template.HTML(buf.String())
	}
	if keep {
		m.cache.Add(key, h)
	}
	return h
}

// Len is the number of cached results.
func (m *Markdown) Len() int { return m.cache.Len() }

// Bytes is the size of the cached HTML.
func (m *Markdown) Bytes() int64 { return m.cache.Bytes() }

// Misses counts the texts that had to be rendered.
func (m *Markdown) Misses() int64 { return m.misses.Load() }
