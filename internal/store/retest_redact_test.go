package store

import (
	"bytes"
	"image/color"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"yars/internal/config"
	"yars/internal/workflow"
)

// shotFixture: srcFixture with a white shot.png on F-003-csrf.
func shotFixture(t *testing.T) (*Store, string) {
	t.Helper()
	s, dir := srcFixture(t)
	if _, err := s.AddAttachment(eng, "F-003-csrf", "shot.png", pngBytes(t, color.White), alice); err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func retestOf(t *testing.T, s *Store, id, source string) {
	t.Helper()
	if err := s.CreateRetest(Engagement{ID: id, Name: "Retest " + id}, source, []string{"F-003-csrf"}, "", uDora); err != nil {
		t.Fatal(err)
	}
}

func shotIn(t *testing.T, s *Store, id string) []byte {
	t.Helper()
	b, err := s.ReadAttachment(id, "F-003-csrf", "attachments/shot.png")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func idsOf(refs []FindingRef) []string {
	var out []string
	for _, r := range refs {
		out = append(out, r.EngID)
	}
	return out
}

// Q12: a redaction reaches every retest made from the engagement and the
// retests of those, as a commit of their own with the redaction noted; a
// copy changed since is left alone.
func TestRedactReachesRetestCopies(t *testing.T) {
	s, dir := shotFixture(t)
	retestOf(t, s, "rt1", eng)
	retestOf(t, s, "rt2", "rt1")
	retestOf(t, s, "rt3", eng)
	gray := pngBytes(t, color.Gray{Y: 64})
	if err := s.ReplaceAttachment("rt3", "F-003-csrf", "shot.png", gray, uAlice); err != nil {
		t.Fatal(err)
	}
	black := pngBytes(t, color.Black)
	rd, err := s.RedactAttachment(eng, "F-003-csrf", "shot.png", black, uAlice)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rd.Redacted, []string{"rt1", "rt2"}) || len(rd.Archived)+len(rd.Failed) != 0 {
		t.Fatalf("report %+v", rd)
	}
	for _, id := range []string{"rt1", "rt2"} {
		if !bytes.Equal(shotIn(t, s, id), black) {
			t.Fatalf("%s: not redacted", id)
		}
		if got := logOf(t, filepath.Join(dir, "engagements", id), "%an|%s"); got != "alice|F-003: redact shot.png" {
			t.Fatalf("%s commit %q", id, got)
		}
		if u, _ := s.DB().Unpurged(id, "F-003"); !u["shot.png"] {
			t.Fatalf("%s: the redaction is not noted", id)
		}
	}
	if !bytes.Equal(shotIn(t, s, "rt3"), gray) {
		t.Fatal("a copy changed since was redacted")
	}
}

// Q12: an archived retest is left as it is and reported.
func TestRedactLeavesArchivedRetest(t *testing.T) {
	s, _ := shotFixture(t)
	retestOf(t, s, "rt1", eng)
	retestOf(t, s, "rt2", eng)
	if err := s.Archive("rt1", uDora); err != nil {
		t.Fatal(err)
	}
	rd, err := s.RedactAttachment(eng, "F-003-csrf", "shot.png", pngBytes(t, color.Black), uAlice)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rd.Archived, []string{"rt1"}) || !reflect.DeepEqual(rd.Redacted, []string{"rt2"}) {
		t.Fatalf("report %+v", rd)
	}
	if !bytes.Equal(shotIn(t, s, "rt1"), pngBytes(t, color.White)) {
		t.Fatal("the archived retest changed")
	}
}

// Q12: a copy the retest has signed off and approved is redacted too (the
// source's redaction, not the redactor's edit there), and stays complete.
func TestRedactReachesLockedCopy(t *testing.T) {
	s, _ := shotFixture(t)
	retestOf(t, s, "rt", eng)
	d := "F-003-csrf"
	s.SetReviewers("rt", d, []string{"bob"}, uDora)
	s.SetRetestResult("rt", d, "fixed", uDora)
	s.UpdateSeverity("rt", d, "high", "", uDora)
	for _, step := range []struct {
		a workflow.Action
		u config.User
	}{{workflow.Submit, uDora}, {workflow.Clear, uBob}, {workflow.Approve, uDora}} {
		if err := s.Transition("rt", d, step.a, "", step.u); err != nil {
			t.Fatal(err)
		}
	}
	// the source is still a draft: its author, a pentester, redacts it
	black := pngBytes(t, color.Black)
	rd, err := s.RedactAttachment(eng, d, "shot.png", black, uAlice)
	if err != nil || !reflect.DeepEqual(rd.Redacted, []string{"rt"}) {
		t.Fatalf("report %+v %v", rd, err)
	}
	if !bytes.Equal(shotIn(t, s, "rt"), black) {
		t.Fatal("the complete copy was not redacted")
	}
	if ref, _ := s.Finding("rt", d); ref.F.Meta.Status != "complete" {
		t.Fatalf("the copy is %s", ref.F.Meta.Status)
	}
}

// Q12: the purge page lists the retests that hold the original in their
// files or history: one redacted along (history), one archived (files), a
// retest of a retest; not one made after the redaction. A director purges
// there too, and after the purge here they are still listed.
func TestRetestHolders(t *testing.T) {
	s, dir := shotFixture(t)
	retestOf(t, s, "rt1", eng)
	retestOf(t, s, "rt2", "rt1")
	retestOf(t, s, "rt3", eng)
	if err := s.Archive("rt3", uDora); err != nil {
		t.Fatal(err)
	}
	if got, err := s.RetestHolders(eng, "F-003-csrf", "shot.png"); err != nil || len(got) != 0 {
		t.Fatalf("before any redaction %v %v", idsOf(got), err)
	}
	if err := s.ReplaceAttachment(eng, "F-003-csrf", "shot.png", pngBytes(t, color.Black), uAlice); err != nil {
		t.Fatal(err)
	}
	retestOf(t, s, "rt4", eng)
	got, err := s.RetestHolders(eng, "F-003-csrf", "shot.png")
	if err != nil || !slices.Equal(idsOf(got), []string{"rt1", "rt3", "rt2"}) || got[0].Dir != "F-003-csrf" {
		t.Fatalf("holders %v %v", idsOf(got), err)
	}
	// rt1's own Purge takes the original out of its first commit, whatever
	// git's log.showRoot says
	white := strings.TrimSpace(gitOut(t, filepath.Join(dir, "engagements", "rt1"), "rev-parse", "HEAD~1:findings/F-003-csrf/attachments/shot.png"))
	gitOut(t, filepath.Join(dir, "engagements", "rt1"), "config", "log.showRoot", "false")
	if err := s.PurgeFromHistory("rt1", "F-003-csrf", "shot.png", uDora); err != nil {
		t.Fatal(err)
	}
	if exec.Command("git", "-C", filepath.Join(dir, "engagements", "rt1"), "cat-file", "-e", white).Run() == nil {
		t.Fatal("the original is still in rt1")
	}
	if err := s.PurgeFromHistory(eng, "F-003-csrf", "shot.png", uDora); err != nil {
		t.Fatal(err)
	}
	if got, err := s.RetestHolders(eng, "F-003-csrf", "shot.png"); err != nil || !slices.Equal(idsOf(got), []string{"rt3", "rt2"}) {
		t.Fatalf("after the purges %v %v", idsOf(got), err)
	}
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return string(out)
}
