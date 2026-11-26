package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/finding"
)

func TestTemplatesSaveListGetDelete(t *testing.T) {
	s, dir := withEngagement(t)
	newTemplate(t, s, "missing-hsts", "Missing HSTS header")
	if got := mainLast(t, dir, "%an|%s"); got != "alice|templates: save missing-hsts" {
		t.Fatalf("commit %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, ".yars", "templates", "missing-hsts.md")); err != nil {
		t.Fatal(err)
	}
	ts, err := s.Templates()
	if err != nil || len(ts) != 1 || ts[0].Slug != "missing-hsts" || ts[0].F.Meta.Title != "Missing HSTS header" || ts[0].F.Meta.Severity != "low" {
		t.Fatalf("list %+v %v", ts, err)
	}
	tp, err := s.Template("missing-hsts")
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := tp.F.Section("Description"); !strings.Contains(body, "HSTS") {
		t.Fatalf("section %q", body)
	}
	for _, bad := range []string{"../x", ".hidden", "a/b", ""} {
		if _, err := s.Template(bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("%q: %v", bad, err)
		}
		if err := s.SaveTemplate(bad, alice, func(*finding.Finding) (*finding.Finding, error) { return s.NewTemplate("x"), nil }); !errors.Is(err, ErrInvalidValue) {
			t.Errorf("save %q: %v", bad, err)
		}
	}
	if err := s.DeleteTemplate("missing-hsts", alice); err != nil {
		t.Fatal(err)
	}
	if ts, _ := s.Templates(); len(ts) != 0 {
		t.Fatalf("after delete %+v", ts)
	}
	if err := s.DeleteTemplate("missing-hsts", alice); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

func TestTemplateSectionConflict(t *testing.T) {
	s, _ := withEngagement(t)
	newTemplate(t, s, "hsts", "HSTS")
	tp, _ := s.Template("hsts")
	body, _ := tp.F.Section("Description")
	if err := s.UpdateTemplateSection("hsts", "Description", "new text", BodyHash(body), alice); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateTemplateSection("hsts", "Description", "other", BodyHash(body), alice); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale base: %v", err)
	}
	if err := s.UpdateTemplateSection("hsts", "Description", "## bad", "", alice); !errors.Is(err, ErrInvalidBody) {
		t.Fatalf("bad body: %v", err)
	}
	tp, _ = s.Template("hsts")
	if body, _ := tp.F.Section("Description"); strings.TrimSpace(body) != "new text" {
		t.Fatalf("body %q", body)
	}
}

func TestCreateFindingFromTemplate(t *testing.T) {
	s, _ := withEngagement(t)
	newTemplate(t, s, "missing-hsts", "Missing HSTS header")
	ref, err := s.CreateFindingFrom(eng, "Missing HSTS on api", "missing-hsts", alice)
	if err != nil {
		t.Fatal(err)
	}
	m := ref.F.Meta
	if m.ID != "F-001" || m.Title != "Missing HSTS on api" || m.Author != "alice" || m.Severity != "low" || !strings.HasPrefix(m.CVSS, "CVSS:3.1/AV:N/AC:H") || m.Extra["template"] != "missing-hsts" {
		t.Fatalf("meta %+v", m)
	}
	got, err := s.Finding(eng, ref.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := got.F.Section("Description"); !strings.Contains(body, "HSTS") {
		t.Fatalf("description %q", body)
	}
	if _, err := s.CreateFindingFrom(eng, "x", "nope", alice); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown template: %v", err)
	}
}
