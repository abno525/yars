package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"yars/internal/config"
	"yars/internal/finding"
	"yars/internal/workflow"
)

var (
	m17Dir = config.User{Username: "dora", Role: "director"}
	m17Pen = config.User{Username: "alice", Role: "pentester"}
)

func newTemplate(t *testing.T, s *Store, slug, title string) {
	t.Helper()
	err := s.SaveTemplate(slug, alice, func(cur *finding.Finding) (*finding.Finding, error) {
		if cur != nil {
			t.Fatalf("template %s exists", slug)
		}
		f := s.NewTemplate(title)
		f.SetSection("Description", "The server does not send HSTS.")
		if err := f.SetMeta("severity", "low"); err != nil {
			return nil, err
		}
		return f, f.SetMeta("cvss", "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N")
	})
	if err != nil {
		t.Fatal(err)
	}
}

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

func TestReportSections(t *testing.T) {
	s, dir := withEngagement(t)
	body, err := s.ReportSection(eng, "Executive summary")
	if err != nil || body != "" {
		t.Fatalf("empty: %q %v", body, err)
	}
	if err := s.UpdateReportSection(eng, "Executive summary", "We found 5 issues.", "", alice); err != nil {
		t.Fatal(err)
	}
	if got := last(t, dir, "%an|%s"); got != "alice|report: edit Executive summary" {
		t.Fatalf("commit %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "engagements", eng, "report", "executive-summary.md")); err != nil {
		t.Fatal(err)
	}
	body, _ = s.ReportSection(eng, "Executive summary")
	if strings.TrimSpace(body) != "We found 5 issues." {
		t.Fatalf("body %q", body)
	}
	if err := s.UpdateReportSection(eng, "Executive summary", "x", BodyHash("stale"), alice); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if err := s.UpdateReportSection(eng, "Executive summary", "## x", "", alice); !errors.Is(err, ErrInvalidBody) {
		t.Fatalf("invalid: %v", err)
	}
	if err := s.Archive(eng, m17Dir); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateReportSection(eng, "Scope", "x", "", alice); !errors.Is(err, ErrArchived) {
		t.Fatalf("archived: %v", err)
	}
}

// Report sections whose names slug alike (no Latin letters, a long shared
// prefix) get files of their own; plain names keep their slug.
func TestReportFileNames(t *testing.T) {
	if ReportFile("Executive summary") != "executive-summary" {
		t.Fatalf("plain name %q", ReportFile("Executive summary"))
	}
	long := strings.Repeat("Findings by business unit and severity ", 2)
	for _, pair := range [][2]string{{"Обзор", "Риски"}, {long + "A", long + "B"}} {
		a, b := ReportFile(pair[0]), ReportFile(pair[1])
		if a == b || !ValidID(a) || !ValidID(b) || len(a) > 60 {
			t.Errorf("%q / %q -> %q / %q", pair[0], pair[1], a, b)
		}
	}
	s, _ := withEngagement(t)
	s.UpdateReportSection(eng, "Обзор", "overview", "", alice)
	s.UpdateReportSection(eng, "Риски", "risks", "", alice)
	if b, _ := s.ReportSection(eng, "Обзор"); strings.TrimSpace(b) != "overview" {
		t.Fatalf("first section %q", b)
	}
}

// A report section renamed in Admin › Structure keeps its text: the file
// moves to the new name in every engagement, archived ones too.
func TestRenameReportSections(t *testing.T) {
	s, dir := withEngagement(t)
	if err := s.UpdateReportSection(eng, "Scope", "The web portal.", "", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateReportSection(eng, "Methodology", "OWASP.", "", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.Archive(eng, m17Dir); err != nil {
		t.Fatal(err)
	}
	if err := s.RenameReportSections(map[string]string{"Scope": "Scope and approach", "Methodology": "methodology"}, alice); err != nil {
		t.Fatal(err)
	}
	if body, _ := s.ReportSection(eng, "Scope and approach"); strings.TrimSpace(body) != "The web portal." {
		t.Fatalf("renamed %q", body)
	}
	if body, _ := s.ReportSection(eng, "Scope"); body != "" {
		t.Fatalf("old name still has %q", body)
	}
	if body, _ := s.ReportSection(eng, "methodology"); strings.TrimSpace(body) != "OWASP." {
		t.Fatalf("same slug %q", body)
	}
	if got := last(t, dir, "%an|%s"); got != "alice|report: rename Scope to Scope and approach" {
		t.Fatalf("commit %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "engagements", eng, "report", "scope.md")); !os.IsNotExist(err) {
		t.Fatalf("old file: %v", err)
	}
}

func TestUpdateEngagementSettings(t *testing.T) {
	s, dir := withEngagement(t)
	e, _ := s.Engagement(eng)
	e.Name, e.Client, e.Start, e.End = "ACME portal", "ACME Ltd", "2026-11-04", "2026-11-07"
	var d *workflow.Denied
	if err := s.UpdateEngagement(e, m17Pen); !errors.As(err, &d) {
		t.Fatalf("pentester: %v", err)
	}
	if err := s.UpdateEngagement(e, m17Dir); err != nil {
		t.Fatal(err)
	}
	if got := last(t, dir, "%an|%s"); got != "dora|engagement "+eng+": settings" {
		t.Fatalf("commit %q", got)
	}
	got, _ := s.Engagement(eng)
	if got.Name != "ACME portal" || got.Client != "ACME Ltd" || got.Start != "2026-11-04" || got.End != "2026-11-07" || got.Type != "pentest" {
		t.Fatalf("saved %+v", got)
	}
	bad := got
	bad.Name = " "
	if err := s.UpdateEngagement(bad, m17Dir); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty name: %v", err)
	}
	bad = got
	bad.Start = "4 Nov"
	if err := s.UpdateEngagement(bad, m17Dir); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("bad date: %v", err)
	}
}

// Configurations apply one at a time, subscribers included: one applied
// while another is still being handed to the subscribers waits, so the
// store and every subscriber end with the last one (D12).
func TestSetConfigInOrder(t *testing.T) {
	s, _ := withEngagement(t)
	var mu sync.Mutex
	last := ""
	gate, entered := make(chan struct{}), make(chan struct{}, 4)
	s.OnConfig(func(c config.Config) {
		entered <- struct{}{}
		if c.Sections[0] == "X" {
			<-gate
		}
		mu.Lock()
		last = c.Sections[0]
		mu.Unlock()
	})
	x, y := s.Config(), s.Config()
	x.Sections, y.Sections = []string{"X"}, []string{"Y"}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); s.SetConfig(x) }()
	<-entered
	done := make(chan struct{})
	go func() { defer wg.Done(); s.SetConfig(y); close(done) }()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
	}
	close(gate)
	wg.Wait()
	if last != "Y" || s.Config().Sections[0] != "Y" {
		t.Fatalf("subscriber has %s, store %v", last, s.Config().Sections)
	}
}

func TestSetConfigApplies(t *testing.T) {
	s, _ := withEngagement(t)
	c := s.Config()
	c.Sections = []string{"Summary", "Fix"}
	s.SetConfig(c)
	ref, err := s.CreateFinding(eng, "x", alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(ref.F.Sections) != 2 || ref.F.Sections[0].Name != "Summary" {
		t.Fatalf("sections %+v", ref.F.Sections)
	}
}
