package store

import (
	"testing"

	"github.com/abno525/yars/internal/gitrepo"
)

// Each template's versions come from git: newest first, numbered from the
// first save; a delete starts the count again. Reading them again at the
// same HEAD starts no git process.
func TestTemplateHistories(t *testing.T) {
	s, _ := withEngagement(t)
	newTemplate(t, s, "hsts", "HSTS")
	bob := gitrepo.Author{Name: "bob", Email: "bob@yars.local"}
	if err := s.UpdateTemplateSection("hsts", "Description", "second", "", bob); err != nil {
		t.Fatal(err)
	}
	newTemplate(t, s, "xss", "XSS")
	hs, err := s.TemplateHistories()
	if err != nil {
		t.Fatal(err)
	}
	h := hs["hsts"]
	if len(h) != 2 || h[0].N != 2 || h[0].Author != "bob" || h[1].N != 1 || h[1].Author != "alice" || h[0].Hash == "" || h[0].Time.IsZero() {
		t.Fatalf("hsts %+v", h)
	}
	if h[1].Subject != "templates: save hsts" {
		t.Fatalf("subject %q", h[1].Subject)
	}
	if x := hs["xss"]; len(x) != 1 || x[0].Author != "alice" {
		t.Fatalf("xss %+v", x)
	}
	before := gitrepo.Spawned()
	if _, err := s.TemplateHistories(); err != nil {
		t.Fatal(err)
	}
	if n := gitrepo.Spawned() - before; n != 0 {
		t.Fatalf("%d git processes for a cached read", n)
	}
	// deleted and made again: a new first version
	if err := s.DeleteTemplate("xss", alice); err != nil {
		t.Fatal(err)
	}
	newTemplate(t, s, "xss", "XSS")
	hs, _ = s.TemplateHistories()
	if x := hs["xss"]; len(x) != 1 || x[0].N != 1 {
		t.Fatalf("xss after delete %+v", x)
	}
}
