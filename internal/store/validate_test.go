package store

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/workflow"
)

// The shared content rules, as the website and git pushes use them.
func TestSharedRules(t *testing.T) {
	cfg := config.Default()
	const crit = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	bad := func(what string, err error, want string) {
		t.Helper()
		if !errors.Is(err, ErrInvalidValue) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v (want %q)", what, err, want)
		}
	}
	bad("bidi title", ValidTitle("Upload ‮gnp.exe"), "hidden text-direction")
	bad("empty title", ValidTitle(""), "one line of 1–200")
	if err := ValidTitle("SQL injection"); err != nil {
		t.Error(err)
	}
	_, err := CheckCVSS(cfg, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	bad("3.0 vector", err, "write "+crit)
	_, err = CheckCVSS(cfg, "CVSS:3.1/C:H/AV:N/AC:L/PR:N/UI:N/S:U/I:H/A:H")
	bad("metric order", err, "write "+crit)
	_, err = CheckCVSS(cfg, "CVSS:3.1/AV:N")
	bad("partial", err, "missing metric")
	if v, err := CheckCVSS(cfg, crit); err != nil || v == nil {
		t.Errorf("canonical vector: %v", err)
	}
	bad("severity vs vector", CheckSeverity(cfg, "low", crit), "severity low does not match the CVSS vector (score 9.8 is critical)")
	bad("unknown severity", CheckSeverity(cfg, "banana", ""), "unknown severity banana")
	if err := CheckSeverity(cfg, "critical", crit); err != nil {
		t.Error(err)
	}
	bad("port", CheckAssets([]finding.Asset{{Host: "h", Port: "0"}}), "port must be 1–65535")
	pt := Engagement{Name: "A", Type: "pentest"}
	bad("type change", CheckEngagement(&pt, Engagement{Name: "A", Type: "retest", Source: "x"}), "keep type: pentest")
	bad("new retest without source", CheckEngagement(nil, Engagement{Name: "A", Type: "retest"}), "names its source")
	bad("dates", CheckEngagement(&pt, Engagement{Name: "A", Type: "pentest", Start: "2026-02-30"}), "YYYY-MM-DD")
	if ps := EngagementProblems(&pt, Engagement{Name: " ", Type: "retest", Source: "x", Start: "2026-02-30", End: "x"}); len(ps) != 4 {
		t.Errorf("every problem: %q", ps)
	}
	if ps := EngagementProblems(nil, Engagement{Name: "A", Start: "2026-02-03", End: "2026-02-01"}); len(ps) != 2 {
		t.Errorf("new engagement: %q", ps)
	}
	bad("binary", CheckAttachment("a.png", []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00"), false), "only images and text")
	bad("exec", CheckAttachment("a.txt", []byte("x"), true), "executable")
	bad("folder", CheckAttachment("a/b.txt", []byte("x"), false), "no folders")
	if err := CheckAttachment("a.txt", []byte("x"), false); err != nil {
		t.Error(err)
	}
}

// A heading of "##" and spaces would make a section with no name, which no
// page can show or edit: the shared check refuses it, for the website and
// pushes alike (backlog, Core).
func TestSectionWithoutNameRefused(t *testing.T) {
	f, err := finding.Parse([]byte("---\nid: F-001\ntitle: X\n---\n\n## Description\n\nText.\n\n##   \n\nOrphan.\n"))
	if err != nil {
		t.Fatal(err)
	}
	ps := FindingProblems(config.Default(), f, nil)
	if len(ps) != 1 || !strings.Contains(ps[0], "a section heading (##) has no name") {
		t.Fatalf("problems %q", ps)
	}
}

// The website's own writes go through the same rules: a pentest's type
// stays when its settings are saved.
func TestEngagementSettingsKeepType(t *testing.T) {
	s, _ := newStore(t)
	if err := s.CreateEngagement(Engagement{ID: "acme", Name: "ACME"}, alice); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateEngagement(Engagement{ID: "acme", Name: "ACME 2", Type: "retest", Source: "other"}, m17Dir); err != nil {
		t.Fatal(err)
	}
	if e, _ := s.Engagement("acme"); e.Type != "pentest" || e.Source != "" || e.Name != "ACME 2" {
		t.Fatalf("engagement %+v", e)
	}
}

// A finding the server already holds with a broken vector (pushed before
// pushes were checked) can still have another part edited on the website.
func TestWebEditOfGrandfatheredFinding(t *testing.T) {
	s, dir := newStore(t)
	s.CreateEngagement(Engagement{ID: "acme", Name: "ACME"}, alice)
	ref, err := s.CreateFinding("acme", "SQLi", alice)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "engagements", "acme", "findings", ref.Dir, "finding.md")
	f := ref.F
	f.SetMeta("cvss", "CVSS:3.1/AV:N")
	os.WriteFile(p, f.Bytes(), 0o644)
	git(t, filepath.Join(dir, "engagements", "acme"), "commit", "-qam", "old push")
	s.Invalidate("acme")
	if err := s.UpdateSection("acme", ref.Dir, "Impact", "Full read.", "", bob); err != nil {
		t.Fatalf("edit refused: %v", err)
	}
}

// A file pushed in its own layout (no blank lines around a body, spaces
// after a heading) stays as it is when a section is saved with the text it
// already has: no commit, and the sign-offs given for it still count
// (backlog, M10).
func TestUnchangedSaveKeepsPushedFile(t *testing.T) {
	s, dir, fd := ready(t)
	repo := filepath.Join(dir, "engagements", eng)
	p := filepath.Join(repo, "findings", fd, "finding.md")
	b, _ := os.ReadFile(p)
	raw := strings.Replace(string(b), "## Impact\n\n", "## Impact  \n", 1)
	raw = strings.TrimRight(raw, "\n") + "\nDB read.\n"
	os.WriteFile(p, []byte(raw), 0o644)
	git(t, repo, "commit", "-qam", "push in another layout")
	s.Invalidate(eng)
	s.SetReviewers(eng, fd, []string{"bob"}, uAlice)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	ref, _ := s.Finding(eng, fd)
	body, _ := ref.F.Section("Impact")
	head := last(t, dir, "%H")
	if err := s.UpdateSection(eng, fd, "Impact", "\r\n"+strings.TrimSpace(body)+"\r\n", "", uAlice); err != nil {
		t.Fatal(err)
	}
	if last(t, dir, "%H") != head {
		t.Fatal("an unchanged save made a commit")
	}
	if got, _ := os.ReadFile(p); string(got) != raw {
		t.Fatalf("the file was rewritten:\n%s", got)
	}
	if ref, _ := s.Finding(eng, fd); !slices.Contains(ref.F.Meta.ClearedBy, "bob") {
		t.Fatal("bob's sign-off was dropped")
	}
}
