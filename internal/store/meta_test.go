package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const eng = "2026-11-acme"

func newFinding(t *testing.T) (*Store, string, string) {
	t.Helper()
	s, dir := withEngagement(t)
	f, err := s.CreateFinding(eng, "SQL injection", alice)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir, f.Dir
}

func load(t *testing.T, s *Store, fdir string) FindingRef {
	t.Helper()
	ref, err := s.Finding(eng, fdir)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestUpdateCVSS(t *testing.T) {
	s, dir, fd := newFinding(t)
	err := s.UpdateCVSS(eng, fd, " cvss:3.1/c:h/av:n/ac:h/pr:n/ui:n/s:u/i:h/a:n", map[string]string{"AC": "race"}, "", bob)
	if err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if m.CVSS != "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" || m.Severity != "high" || m.CVSSReasons["AC"] != "race" {
		t.Fatalf("meta %+v", m)
	}
	if got := last(t, dir, "%an|%s"); got != "bob|F-001: set CVSS 7.4" {
		t.Fatalf("commit %q", got)
	}
}

func TestUpdateCVSSInvalid(t *testing.T) {
	s, dir, fd := newFinding(t)
	before := last(t, dir, "%H")
	if err := s.UpdateCVSS(eng, fd, "8.1", nil, "", bob); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("err %v", err)
	}
	if last(t, dir, "%H") != before {
		t.Fatal("commit made")
	}
}

func TestUpdateCVSSConflict(t *testing.T) {
	s, _, fd := newFinding(t)
	base := CVSSHash(load(t, s, fd).F.Meta)
	if err := s.UpdateCVSS(eng, fd, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil, base, alice); err != nil {
		t.Fatal(err)
	}
	err := s.UpdateCVSS(eng, fd, "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", nil, base, bob)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err %v", err)
	}
}

func TestUpdateCVSSReasonsKept(t *testing.T) {
	s, _, fd := newFinding(t)
	s.UpdateCVSS(eng, fd, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", map[string]string{"AC": "x"}, "", bob)
	if err := s.UpdateCVSS(eng, fd, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", map[string]string{}, "", bob); err != nil {
		t.Fatal(err)
	}
	if r := load(t, s, fd).F.Meta.CVSSReasons["AC"]; r != "x" {
		t.Fatalf("reason %q", r)
	}
	// an explicitly emptied reason is removed
	s.UpdateCVSS(eng, fd, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", map[string]string{"AC": ""}, "", bob)
	if _, ok := load(t, s, fd).F.Meta.CVSSReasons["AC"]; ok {
		t.Fatal("emptied reason kept")
	}
}

func TestUpdateCVSSClear(t *testing.T) {
	s, dir, fd := newFinding(t)
	s.UpdateCVSS(eng, fd, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", nil, "", bob)
	if err := s.UpdateCVSS(eng, fd, "", nil, "", bob); err != nil {
		t.Fatal(err)
	}
	m := load(t, s, fd).F.Meta
	if m.CVSS != "" || m.Severity != "high" {
		t.Fatalf("meta %+v", m)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "engagements", eng, "findings", fd, "finding.md"))
	if strings.Contains(string(b), "cvss:") {
		t.Fatalf("cvss key left:\n%s", b)
	}
	if got := last(t, dir, "%s"); got != "F-001: clear CVSS" {
		t.Fatalf("commit %q", got)
	}
}

func TestUpdateSeverity(t *testing.T) {
	s, dir, fd := newFinding(t)
	if err := s.UpdateSeverity(eng, fd, "medium", "", bob); err != nil {
		t.Fatal(err)
	}
	if load(t, s, fd).F.Meta.Severity != "medium" || last(t, dir, "%s") != "F-001: set severity medium" {
		t.Fatal("severity not set")
	}
	if err := s.UpdateSeverity(eng, fd, "urgent", "", bob); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("err %v", err)
	}
	s.UpdateCVSS(eng, fd, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", nil, "", bob)
	if err := s.UpdateSeverity(eng, fd, "low", "", bob); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("err with vector %v", err)
	}
}

func TestUpdateSeverityConflict(t *testing.T) {
	s, _, fd := newFinding(t)
	base := SeverityHash(load(t, s, fd).F.Meta)
	if err := s.UpdateSeverity(eng, fd, "high", base, alice); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSeverity(eng, fd, "low", base, bob); !errors.Is(err, ErrConflict) {
		t.Fatalf("err %v", err)
	}
}

func TestUpdateDetailsRoundTrip(t *testing.T) {
	s, dir, fd := newFinding(t)
	path := filepath.Join(dir, "engagements", eng, "findings", fd, "finding.md")
	// pre-existing unknown row
	ref := load(t, s, fd)
	ref.F.SetMeta("details", map[string]string{"Old row": "legacy"})
	os.WriteFile(path, ref.F.Bytes(), 0o644)
	git(t, dir, "commit", "-qam", "seed")

	vals := map[string]string{
		"Location":        "<script>x</script>\r\n- a: b\n# c  ",
		"Business impact": "x",
	}
	if err := s.UpdateDetails(eng, fd, vals, "", bob); err != nil {
		t.Fatal(err)
	}
	d := load(t, s, fd).F.Meta.Details
	if d["Location"] != "<script>x</script>\n- a: b\n# c" || d["Business impact"] != "x" || d["Old row"] != "legacy" {
		t.Fatalf("details %q", d)
	}
	b, _ := os.ReadFile(path)
	if strings.Index(string(b), "Location") > strings.Index(string(b), "Business impact") {
		t.Fatalf("order:\n%s", b)
	}
	if got := last(t, dir, "%an|%s"); got != "bob|F-001: edit details" {
		t.Fatalf("commit %q", got)
	}
}

func TestUpdateDetailsConflict(t *testing.T) {
	s, _, fd := newFinding(t)
	base := DetailsHash(load(t, s, fd).F.Meta)
	s.UpdateDetails(eng, fd, map[string]string{"Location": "a"}, base, alice)
	if err := s.UpdateDetails(eng, fd, map[string]string{"Location": "b"}, base, bob); !errors.Is(err, ErrConflict) {
		t.Fatalf("err %v", err)
	}
}

func TestUpdateDetailsNoop(t *testing.T) {
	s, dir, fd := newFinding(t)
	s.UpdateDetails(eng, fd, map[string]string{"Location": "a"}, "", alice)
	h := last(t, dir, "%H")
	if err := s.UpdateDetails(eng, fd, map[string]string{"Location": "a"}, "", alice); err != nil {
		t.Fatal(err)
	}
	if last(t, dir, "%H") != h {
		t.Fatal("no-op made a commit")
	}
}
