package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
