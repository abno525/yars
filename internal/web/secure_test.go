package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// templates returns every template file by name.
func templates(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := templateFS.ReadFile(p)
		out[p] = string(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The page's script policy allows no inline code: no on… handlers, no inline
// scripts, no style attributes.
func TestNoInlineHandlersInTemplates(t *testing.T) {
	handler := regexp.MustCompile(`\son[a-z]+\s*=`)
	script := regexp.MustCompile(`<script\b[^>]*>`)
	for name, src := range templates(t) {
		if m := handler.FindString(src); m != "" {
			t.Errorf("%s: inline handler %q", name, m)
		}
		for _, tag := range script.FindAllString(src, -1) {
			if !strings.Contains(tag, "src=") {
				t.Errorf("%s: inline script %q", name, tag)
			}
		}
		if strings.Contains(src, `style="`) {
			t.Errorf("%s: style attribute", name)
		}
	}
}

// htmx evaluates no code: no hx-on, no trigger filters.
func TestNoEvaluatedTriggers(t *testing.T) {
	trigger := regexp.MustCompile(`hx-trigger="[^"]*"`)
	for name, src := range templates(t) {
		if strings.Contains(src, "hx-on") {
			t.Errorf("%s: hx-on", name)
		}
		for _, m := range trigger.FindAllString(src, -1) {
			if strings.Contains(m, "[") {
				t.Errorf("%s: evaluated filter in %s", name, m)
			}
		}
	}
}

func TestHtmxNeverEvaluates(t *testing.T) {
	e := setup(t)
	b := e.do(t, "", "GET", "/login", nil, nil).Body.String()
	if !strings.Contains(b, `"allowEval":false`) || !strings.Contains(b, `"includeIndicatorStyles":false`) {
		t.Fatalf("htmx config lacks allowEval or includeIndicatorStyles:\n%s", between(b, "<head>", "</head>"))
	}
}

// Comment and confirm buttons are wired in app.js through data attributes.
func TestCommentAndConfirmHooks(t *testing.T) {
	e := setup(t)
	if b := e.do(t, "alice", "GET", "/e/acme/f/001", nil, nil).Body.String(); !strings.Contains(b, `data-comment="Description"`) {
		t.Fatal("the finding page has no data-comment button")
	}
	if b := e.do(t, "dora", "GET", "/", nil, nil).Body.String(); !strings.Contains(b, `data-confirm="Archive ACME Web?"`) {
		t.Fatal("the engagements list has no data-confirm Archive button")
	}
	js := e.do(t, "alice", "GET", staticPrefix()+"/app.js", nil, nil).Body.String()
	for _, want := range []string{"data-comment", "data-confirm", "htmx:beforeRequest", "yars:enter", "yars:rowclick"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
}
