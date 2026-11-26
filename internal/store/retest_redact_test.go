package store

import (
	"bytes"
	"image/color"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/workflow"
)

// shotFixture: srcFixture with a white shot.png on F-003-csrf; alice and
// bob are on the team (and so on its retests').
func shotFixture(t *testing.T) (*Store, string) {
	t.Helper()
	s, dir := srcFixture(t)
	if _, err := s.AddAttachment(eng, "F-003-csrf", "shot.png", pngBytes(t, color.White), alice); err != nil {
		t.Fatal(err)
	}
	if err := s.DB().AddMembers(eng, "alice", "bob"); err != nil {
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

// Q12: a copy is written as the redactor, under the retest's own rules: a
// pentester's redaction leaves a copy approved there (locked to directors)
// and reports it; a director's next redaction reaches it, and the copy
// stays complete.
func TestRedactLeavesLockedCopy(t *testing.T) {
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
	rd, err := s.RedactAttachment(eng, d, "shot.png", pngBytes(t, color.Black), uAlice)
	if err != nil || !reflect.DeepEqual(rd.Locked, []string{"rt"}) || len(rd.Redacted) != 0 {
		t.Fatalf("report %+v %v", rd, err)
	}
	if !bytes.Equal(shotIn(t, s, "rt"), pngBytes(t, color.White)) {
		t.Fatal("a pentester's redaction changed the complete copy")
	}
	gray := pngBytes(t, color.Gray{Y: 64})
	rd, err = s.RedactAttachment(eng, d, "shot.png", gray, uDora)
	if err != nil || !reflect.DeepEqual(rd.Redacted, []string{"rt"}) {
		t.Fatalf("director's report %+v %v", rd, err)
	}
	if !bytes.Equal(shotIn(t, s, "rt"), gray) {
		t.Fatal("the director's redaction did not reach the complete copy")
	}
	if ref, _ := s.Finding("rt", d); ref.F.Meta.Status != "complete" {
		t.Fatalf("the copy is %s", ref.F.Meta.Status)
	}
}

// Q12: a redactor not on a retest's team leaves its copy as it is; the
// report keeps it apart (the redactor is not told its ID).
func TestRedactLeavesRetestNotSeen(t *testing.T) {
	s, _ := shotFixture(t)
	retestOf(t, s, "rt1", eng)
	retestOf(t, s, "rt2", eng)
	if err := s.RemoveMember("rt2", "alice", uDora); err != nil {
		t.Fatal(err)
	}
	rd, err := s.RedactAttachment(eng, "F-003-csrf", "shot.png", pngBytes(t, color.Black), uAlice)
	if err != nil || !reflect.DeepEqual(rd.Redacted, []string{"rt1"}) || !reflect.DeepEqual(rd.Hidden, []string{"rt2"}) {
		t.Fatalf("report %+v %v", rd, err)
	}
	if !bytes.Equal(shotIn(t, s, "rt2"), pngBytes(t, color.White)) {
		t.Fatal("a retest the redactor cannot see was changed")
	}
}

// Q12: a copy an earlier redaction left (its retest archived then) still
// holds a version the source had, so it has not changed since: a later
// redaction reports it while archived and reaches it once it is open
// again, also after the source purged those versions.
func TestRedactReachesCopyLeftBefore(t *testing.T) {
	s, _ := shotFixture(t)
	retestOf(t, s, "rt1", eng)
	if err := s.Archive("rt1", uDora); err != nil {
		t.Fatal(err)
	}
	for _, c := range []color.Color{color.Black, color.Gray{Y: 64}} {
		rd, err := s.RedactAttachment(eng, "F-003-csrf", "shot.png", pngBytes(t, c), uAlice)
		if err != nil || !reflect.DeepEqual(rd.Archived, []string{"rt1"}) {
			t.Fatalf("report %+v %v", rd, err)
		}
	}
	if err := s.PurgeFromHistory(eng, "F-003-csrf", "shot.png", uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.Unarchive("rt1", uDora); err != nil {
		t.Fatal(err)
	}
	dark := pngBytes(t, color.Gray{Y: 32})
	rd, err := s.RedactAttachment(eng, "F-003-csrf", "shot.png", dark, uAlice)
	if err != nil || !reflect.DeepEqual(rd.Redacted, []string{"rt1"}) {
		t.Fatalf("report %+v %v", rd, err)
	}
	if !bytes.Equal(shotIn(t, s, "rt1"), dark) {
		t.Fatal("the copy left before was not redacted")
	}
}

// Q12: a copy whose write fails is reported, and the others go on.
func TestRedactReportsFailedCopy(t *testing.T) {
	s, dir := shotFixture(t)
	retestOf(t, s, "rt1", eng)
	retestOf(t, s, "rt2", eng)
	lock := filepath.Join(dir, "engagements", "rt1", ".git", "index.lock")
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	rd, err := s.RedactAttachment(eng, "F-003-csrf", "shot.png", pngBytes(t, color.Black), uAlice)
	if err != nil || !reflect.DeepEqual(rd.Failed, []string{"rt1"}) || !reflect.DeepEqual(rd.Redacted, []string{"rt2"}) {
		t.Fatalf("report %+v %v", rd, err)
	}
	if !bytes.Equal(shotIn(t, s, "rt1"), pngBytes(t, color.White)) {
		t.Fatal("the failed copy was not put back")
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
	if got, unread, err := s.RetestHolders(eng, "F-003-csrf", "shot.png"); err != nil || len(got) != 0 || len(unread) != 0 {
		t.Fatalf("before any redaction %v %v %v", idsOf(got), unread, err)
	}
	if err := s.ReplaceAttachment(eng, "F-003-csrf", "shot.png", pngBytes(t, color.Black), uAlice); err != nil {
		t.Fatal(err)
	}
	retestOf(t, s, "rt4", eng)
	got, unread, err := s.RetestHolders(eng, "F-003-csrf", "shot.png")
	if err != nil || !slices.Equal(idsOf(got), []string{"rt1", "rt3", "rt2"}) || got[0].Dir != "F-003-csrf" || len(unread) != 0 {
		t.Fatalf("holders %v %v %v", idsOf(got), unread, err)
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
	if got, unread, err := s.RetestHolders(eng, "F-003-csrf", "shot.png"); err != nil || !slices.Equal(idsOf(got), []string{"rt3", "rt2"}) || len(unread) != 0 {
		t.Fatalf("after the purges %v %v %v", idsOf(got), unread, err)
	}
}

// Q12: a retest whose copy was deleted since (a director's push) still
// holds the original in its history: listed, with no finding to link.
func TestRetestHoldersCopyGone(t *testing.T) {
	s, dir := shotFixture(t)
	retestOf(t, s, "rt1", eng)
	repo := filepath.Join(dir, "engagements", "rt1")
	gitOut(t, repo, "rm", "-rq", "findings/F-003-csrf")
	gitOut(t, repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "delete F-003")
	s.Invalidate("rt1")
	if err := s.ReplaceAttachment(eng, "F-003-csrf", "shot.png", pngBytes(t, color.Black), uAlice); err != nil {
		t.Fatal(err)
	}
	got, unread, err := s.RetestHolders(eng, "F-003-csrf", "shot.png")
	if err != nil || !slices.Equal(idsOf(got), []string{"rt1"}) || got[0].Dir != "" || len(unread) != 0 {
		t.Fatalf("holders %+v %v %v", got, unread, err)
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
