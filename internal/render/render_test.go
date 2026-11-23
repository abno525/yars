package render

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestHTMLCachesBySource(t *testing.T) {
	m := New(5000)
	a := m.HTML("**bold**")
	if !strings.Contains(string(a), "<strong>bold</strong>") {
		t.Fatalf("got %q", a)
	}
	if b := m.HTML("**bold**"); b != a {
		t.Fatalf("second render differs: %q", b)
	}
	if m.Misses() != 1 || m.Len() != 1 {
		t.Fatalf("misses %d len %d, want 1/1", m.Misses(), m.Len())
	}
	m.HTML("other")
	if m.Misses() != 2 || m.Len() != 2 {
		t.Fatalf("misses %d len %d, want 2/2", m.Misses(), m.Len())
	}
}

func TestHTMLBounded(t *testing.T) {
	m := New(3)
	for i := range 10 {
		m.HTML(fmt.Sprint("text ", i))
	}
	if m.Len() != 3 {
		t.Fatalf("len %d, want 3", m.Len())
	}
}

func TestHTMLNoRawHTML(t *testing.T) {
	m := New(10)
	if h := m.HTML("hi <script>alert(1)</script>"); strings.Contains(string(h), "<script>") {
		t.Fatalf("raw html passed: %q", h)
	}
}

// Raw HTML is shown as the text it is, escaped, never dropped: a message
// made only of HTML stays readable (and an @mention in it visible).
func TestHTMLRawShownEscaped(t *testing.T) {
	m := New(10)
	for src, want := range map[string]string{
		"<script>alert(1)</script> @rev1":       "&lt;script&gt;alert(1)&lt;/script&gt; @rev1",
		"<iframe src=\"x\"></iframe>\n\n@rev1":  "&lt;iframe src=&quot;x&quot;&gt;&lt;/iframe&gt;",
		"hi <img src=x onerror=alert(1)> there": "hi &lt;img src=x onerror=alert(1)&gt; there",
		"<div>\nblock\n</div>":                  "&lt;div&gt;<br>\nblock<br>\n&lt;/div&gt;",
	} {
		h := string(m.HTML(src))
		if !strings.Contains(h, want) || strings.Contains(h, "omitted") || strings.Contains(h, "<script") || strings.Contains(h, "<img") || strings.Contains(h, "<iframe") {
			t.Errorf("%q rendered %q, want it to contain %q", src, h, want)
		}
	}
}

func TestHTMLConcurrent(t *testing.T) {
	m := New(50)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 200 {
				m.HTML(fmt.Sprint("x ", (i+j)%80))
			}
		}()
	}
	wg.Wait()
	if m.Len() > 50 {
		t.Fatalf("len %d", m.Len())
	}
}
