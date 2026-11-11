package store

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"yars/internal/chat"
	"yars/internal/finding"
	"yars/internal/workflow"
)

var toBusiness = map[string]string{"Impact": "Business impact"}

// raw reads a finding's file as it is on disk.
func raw(t *testing.T, dir, engID, fd string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "engagements", engID, "findings", fd, "finding.md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// subjects are the last n commit subjects of a repository, newest first.
func subjects(t *testing.T, repo string, n string) []string {
	t.Helper()
	out, err := exec.Command("git", "-C", repo, "log", "-"+n, "--format=%s").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

// a heading a push wrote twice is renamed in both places, text kept
func TestRenameSectionEveryHeading(t *testing.T) {
	f := finding.New("", "SQL injection", "", []string{"Impact"})
	f.SetSection("Impact", "Data loss.")
	f.Sections = append(f.Sections, finding.Section{Name: "Impact", Body: "Downtime."})
	apply, err := renamer("section", []string{"Impact"}, toBusiness, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := apply(f); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range f.Sections {
		got = append(got, x.Name+": "+strings.TrimSpace(x.Body))
	}
	if !slices.Equal(got, []string{"Business impact: Data loss.", "Business impact: Downtime."}) {
		t.Fatalf("sections %q", got)
	}
}

// Q10: a section renamed in Admin › Structure is renamed in every finding,
// one commit each.
func TestRenameSectionRewritesFindings(t *testing.T) {
	s, dir, fd := newFinding(t)
	f2, err := s.CreateFinding(eng, "Stored XSS", alice)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{fd, f2.Dir} {
		if err := s.UpdateSection(eng, d, "Impact", "Data loss.", "", alice); err != nil {
			t.Fatal(err)
		}
	}
	changed, err := s.RenameNames("section", toBusiness, alice)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{fd, f2.Dir} {
		b := raw(t, dir, eng, d)
		if !strings.Contains(b, "## Business impact\n") || strings.Contains(b, "## Impact\n") || !strings.Contains(b, "Data loss.") {
			t.Fatalf("%s:\n%s", d, b)
		}
	}
	if !slices.Equal(changed, []string{eng + "/F-001", eng + "/F-002"}) {
		t.Fatalf("changed %v", changed)
	}
	got := subjects(t, filepath.Join(dir, "engagements", eng), "2")
	if !slices.Equal(got, []string{"F-002: rename section Impact to Business impact", "F-001: rename section Impact to Business impact"}) {
		t.Fatalf("commits %v", got)
	}
}

// A rename changes no text a reviewer read: approvals and sign-offs stay.
func TestRenameKeepsApprovalAndSignOff(t *testing.T) {
	s, _, fd := ready(t)
	f2, _ := s.CreateFinding(eng, "Stored XSS", alice)
	s.SetReviewers(eng, f2.Dir, []string{"bob"}, uAlice)
	s.UpdateSeverity(eng, f2.Dir, "low", "", alice)
	for _, d := range []string{fd, f2.Dir} {
		if err := s.Transition(eng, d, workflow.Submit, "", uAlice); err != nil {
			t.Fatal(err)
		}
		if err := s.Transition(eng, d, workflow.Clear, "", uBob); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RenameNames("section", toBusiness, alice); err != nil {
		t.Fatal(err)
	}
	if st := load(t, s, fd).F.Meta.Status; st != "complete" {
		t.Fatalf("approved finding is %s after the rename", st)
	}
	if m := load(t, s, f2.Dir).F.Meta; m.Status != "verification" || !slices.Contains(m.ClearedBy, "bob") {
		t.Fatalf("signed-off finding: %s cleared by %v", m.Status, m.ClearedBy)
	}
}

// The last check run moves with the content: it is still current.
func TestRenameKeepsCheckCurrent(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, "- id: none\n  target: title\n  regex_forbid: 'zzz'\n")
	checkNow(t, s, fd)
	if g, err := s.CheckGate(eng, fd); err != nil || g != "" {
		t.Fatalf("before: %q %v", g, err)
	}
	if _, err := s.RenameNames("section", toBusiness, alice); err != nil {
		t.Fatal(err)
	}
	if g, err := s.CheckGate(eng, fd); err != nil || g != "" {
		t.Fatalf("after the rename the check is %q %v", g, err)
	}
}

// Comments on a renamed section follow it.
func TestRenameMovesChatSection(t *testing.T) {
	s, _, fd := newFinding(t)
	if _, err := s.PostChat(eng, fd, chat.Message{Text: "which data?", Section: "Impact"}, uBob); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RenameNames("section", toBusiness, alice); err != nil {
		t.Fatal(err)
	}
	msgs, _ := s.Chat(eng, fd)
	if len(msgs) != 1 || msgs[0].Section != "Business impact" {
		t.Fatalf("messages %+v", msgs)
	}
}

// A details row and a manual severity are renamed; a severity derived from
// a CVSS vector stays.
func TestRenameDetailsRowAndSeverity(t *testing.T) {
	s, dir, fd := newFinding(t)
	if err := s.UpdateDetails(eng, fd, map[string]string{"Location": "/login"}, "", alice); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSeverity(eng, fd, "low", "", alice); err != nil {
		t.Fatal(err)
	}
	f2, _ := s.CreateFinding(eng, "Stored XSS", alice)
	if err := s.UpdateCVSS(eng, f2.Dir, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", nil, "", alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RenameNames("details row", map[string]string{"Location": "Where"}, alice); err != nil {
		t.Fatal(err)
	}
	if d := load(t, s, fd).F.Meta.Details; d["Where"] != "/login" || d["Location"] != "" {
		t.Fatalf("details %v", d)
	}
	if _, err := s.RenameNames("severity", map[string]string{"low": "minor", "medium": "moderate"}, alice); err != nil {
		t.Fatal(err)
	}
	if sev := load(t, s, fd).F.Meta.Severity; sev != "minor" {
		t.Fatalf("manual severity %q", sev)
	}
	if b := raw(t, dir, eng, f2.Dir); strings.Contains(b, "moderate") {
		t.Fatalf("a CVSS-derived severity was renamed:\n%s", b)
	}
}

// Templates are rewritten too, in one commit of the main repo.
func TestRenameTemplates(t *testing.T) {
	s, dir := withEngagement(t)
	tpl := finding.New("", "SQL injection", "", []string{"Description", "Impact"})
	tpl.SetSection("Impact", "Data loss.")
	if err := s.SaveTemplate("sqli", alice, func(*finding.Finding) (*finding.Finding, error) { return tpl, nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RenameNames("section", toBusiness, alice); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, TemplatesDir, "sqli.md"))
	if !strings.Contains(string(b), "## Business impact\n") || strings.Contains(string(b), "## Impact\n") {
		t.Fatalf("template:\n%s", b)
	}
	if got := mainLast(t, dir, "%s"); got != "templates: rename section Impact to Business impact" {
		t.Fatalf("commit %q", got)
	}
}

// A rename that fails half-way says which findings were done.
func TestRenameReportsPartialFailure(t *testing.T) {
	s, dir, _ := newFinding(t)
	if err := s.CreateEngagement(Engagement{ID: "zz-beta", Name: "Beta"}, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateFinding("zz-beta", "Open redirect", alice); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, "engagements", "zz-beta", ".git", "index.lock")
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(lock)
	changed, err := s.RenameNames("section", toBusiness, alice)
	if err == nil || !strings.Contains(err.Error(), "zz-beta") {
		t.Fatalf("err %v", err)
	}
	if !slices.Equal(changed, []string{eng + "/F-001"}) {
		t.Fatalf("changed %v", changed)
	}
}
