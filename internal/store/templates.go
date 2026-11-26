package store

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/gitrepo"
)

// TemplatesDir holds finding templates in the main repo: one finding file
// (front matter and sections) per template, named <slug>.md.
const TemplatesDir = ".yars/templates"

// TemplateKey is the front-matter key naming the template a finding was
// created from (usage counts come from it).
const TemplateKey = "template"

// Template is one finding template.
type Template struct {
	Slug string
	F    *finding.Finding
}

// ValidSlug accepts template names: path-safe, no extension.
func ValidSlug(slug string) bool { return ValidID(slug) && !strings.Contains(slug, ".") }

func templatePath(slug string) string { return path.Join(TemplatesDir, slug+".md") }

// NewTemplate is an empty template with the configured sections.
func (s *Store) NewTemplate(title string) *finding.Finding {
	f := finding.New("", strings.TrimSpace(title), "", s.Config().Sections)
	f.Meta.Status = ""
	return f
}

// Templates lists the templates, sorted by title. Unreadable files are
// skipped.
func (s *Store) Templates() ([]Template, error) {
	ents, err := s.readDir(TemplatesDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Template
	for _, e := range ents {
		slug, ok := strings.CutSuffix(e.Name(), ".md")
		if !ok || e.IsDir() || !ValidSlug(slug) {
			continue
		}
		if t, err := s.Template(slug); err == nil {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].F.Meta.Title), strings.ToLower(out[j].F.Meta.Title)
		if a != b {
			return a < b
		}
		return out[i].Slug < out[j].Slug
	})
	return out, nil
}

// Template reads one template.
func (s *Store) Template(slug string) (Template, error) {
	if !ValidSlug(slug) {
		return Template{}, ErrNotFound
	}
	b, err := s.readFile(templatePath(slug))
	if errors.Is(err, fs.ErrNotExist) {
		return Template{}, ErrNotFound
	}
	if err != nil {
		return Template{}, err
	}
	f, err := finding.Parse(b)
	if err != nil {
		return Template{}, fmt.Errorf("template %s: %w", slug, err)
	}
	f.Meta.Title = CleanTitle(f.Meta.Title) // as for findings: no bidi controls shown
	return Template{Slug: slug, F: f}, nil
}

// SaveTemplate changes (or creates) template slug with one settings commit
// as a. edit gets the current template (nil when there is none) and
// returns the new one; its errors are returned unchanged.
func (s *Store) SaveTemplate(slug string, a gitrepo.Author, edit func(cur *finding.Finding) (*finding.Finding, error)) error {
	if !ValidSlug(slug) {
		return fmt.Errorf("%w: template name %q", ErrInvalidValue, slug)
	}
	p := templatePath(slug)
	return s.EditSettings("templates: save "+slug, a, func(read func(string) ([]byte, error)) ([]SettingsFile, error) {
		var cur *finding.Finding
		b, err := read(p)
		switch {
		case err == nil:
			if cur, err = finding.Parse(b); err != nil {
				return nil, fmt.Errorf("template %s: %w", slug, err)
			}
		case !errors.Is(err, fs.ErrNotExist):
			return nil, err
		}
		next, err := edit(cur)
		if err != nil || next == nil {
			return nil, err
		}
		nb := next.Bytes()
		if b != nil && string(nb) == string(b) {
			return nil, nil
		}
		return []SettingsFile{{Path: p, Data: nb}}, nil
	}, nil)
}

// UpdateTemplateSection replaces one section of a template; a non-empty
// base must be BodyHash of the section's current body (else ErrConflict).
func (s *Store) UpdateTemplateSection(slug, section, body, base string, a gitrepo.Author) error {
	if section == "" || section != strings.TrimSpace(section) || strings.ContainsAny(section, "\r\n") || strings.HasPrefix(section, "#") {
		return fmt.Errorf("%w: invalid section name %q", ErrInvalidBody, section)
	}
	if err := finding.ValidateBody(body); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidBody, err)
	}
	return s.SaveTemplate(slug, a, func(cur *finding.Finding) (*finding.Finding, error) {
		if cur == nil {
			return nil, ErrNotFound
		}
		if old, _ := cur.Section(section); base != "" && BodyHash(old) != base {
			return nil, ErrConflict
		}
		cur.SetSection(section, body)
		return cur, nil
	})
}

// TemplateVersion is one commit of a template file: N counts from 1 (the
// save that made it).
type TemplateVersion struct {
	N                     int
	Hash, Author, Subject string
	Time                  time.Time
}

// TemplateHistories returns every template's versions from git, newest
// first, by slug. A template deleted and made again starts at 1. It runs one
// git process, and none while the main repo's HEAD is unchanged.
func (s *Store) TemplateHistories() (map[string][]TemplateVersion, error) {
	head, err := s.head("")
	if err != nil {
		return nil, err
	}
	s.tplHistMu.Lock()
	defer s.tplHistMu.Unlock()
	if s.tplHist != nil && head != "" && s.tplHistAt == head {
		return s.tplHist, nil
	}
	es, err := s.repo.LogDir(TemplatesDir)
	if err != nil {
		return nil, err
	}
	out := map[string][]TemplateVersion{}
	ended := map[string]bool{} // deleted at a newer commit: older ones don't count
	for _, e := range es {
		for _, p := range e.Paths {
			slug, ok := strings.CutSuffix(strings.TrimPrefix(p, TemplatesDir+"/"), ".md")
			if !ok || !ValidSlug(slug) || ended[slug] {
				continue
			}
			if e.Subject == "templates: delete "+slug {
				ended[slug] = true
				continue
			}
			out[slug] = append(out[slug], TemplateVersion{Hash: e.Hash, Author: e.Author, Subject: e.Subject, Time: e.Time})
		}
	}
	for _, vs := range out {
		for i := range vs {
			vs[i].N = len(vs) - i
		}
	}
	s.tplHist, s.tplHistAt = out, head
	return out, nil
}

// DeleteTemplate removes a template with one settings commit.
func (s *Store) DeleteTemplate(slug string, a gitrepo.Author) error {
	if !ValidSlug(slug) {
		return ErrNotFound
	}
	p := templatePath(slug)
	return s.EditSettings("templates: delete "+slug, a, func(read func(string) ([]byte, error)) ([]SettingsFile, error) {
		if _, err := read(p); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, ErrNotFound
			}
			return nil, err
		}
		return []SettingsFile{{Path: p}}, nil
	}, nil)
}

// CreateFindingFrom adds a finding made from template slug: its sections,
// severity, CVSS and details, with the new id, title and author, and the
// template's name in the front matter.
func (s *Store) CreateFindingFrom(engID, title, slug string, a gitrepo.Author) (FindingRef, error) {
	title = CleanTitle(title)
	t, err := s.Template(slug)
	if err != nil {
		return FindingRef{}, err
	}
	raw := t.F.Bytes()
	return s.createFinding(engID, title, a, func(id string) (*finding.Finding, error) {
		f, err := finding.Parse(raw)
		if err != nil {
			return nil, err
		}
		for _, kv := range []struct {
			k string
			v any
		}{{"id", id}, {"title", strings.TrimSpace(title)}, {"author", a.Name}, {TemplateKey, slug}} {
			if err := f.SetMeta(kv.k, kv.v); err != nil {
				return nil, err
			}
		}
		f.Meta.Status = "draft"
		return f, nil
	})
}
