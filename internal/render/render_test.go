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
