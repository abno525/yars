package store

import (
	"bytes"
	"errors"
	"image/color"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"yars/internal/workflow"
)

// redacted makes a finding (ready to submit) with an image redacted once:
// its original is in the engagement's history.
func redacted(t *testing.T) (s *Store, dir, fd, name, oldBlob, curBlob string) {
	t.Helper()
	s, dir, fd = ready(t)
	name, err := s.AddAttachment(eng, fd, "shot.png", pngBytes(t, color.White), uAlice)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceAttachment(eng, fd, name, pngBytes(t, color.Black), uAlice); err != nil {
		t.Fatal(err)
	}
	p := "findings/" + fd + "/attachments/" + name
	return s, dir, fd, name, engGit(t, dir, "rev-parse", "HEAD~1:"+p), engGit(t, dir, "rev-parse", "HEAD:"+p)
}

// engGit runs git in the test engagement's repository.
func engGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", filepath.Join(dir, "engagements", eng)}, args...)...).Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// hasBlob reports whether the engagement's repository holds the object.
func hasBlob(dir, blob string) bool {
	return exec.Command("git", "-C", filepath.Join(dir, "engagements", eng), "cat-file", "-e", blob).Run() == nil
}

// D28: the original of a redacted image leaves the history; the current
// image stays; the purged blob is remembered.
func TestPurgeRemovesOldBlob(t *testing.T) {
	s, dir, fd, name, oldBlob, curBlob := redacted(t)
	if err := s.PurgeFromHistory(eng, fd, name, uDora); err != nil {
		t.Fatal(err)
	}
	if hasBlob(dir, oldBlob) || !hasBlob(dir, curBlob) {
		t.Fatalf("old kept %v, current kept %v", hasBlob(dir, oldBlob), hasBlob(dir, curBlob))
	}
	if hasOriginal(t, s, fd, name) {
		t.Fatal("still marked after the purge")
	}
	if b, err := s.DB().PurgedBlobs(eng); err != nil || b[oldBlob] != name {
		t.Fatalf("purged blobs %v %v", b, err)
	}
	if l, _ := s.DB().AuditLog(1); len(l) != 1 || l[0].Action != "attachment.purge" || l[0].Target != eng+"/F-001/"+name || l[0].Actor != "dora" {
		t.Fatalf("audit %+v", l)
	}
}

// D28: only a director purges; not on an archived engagement; only a real
// attachment name.
func TestPurgeDirectorOnly(t *testing.T) {
	s, dir, fd, name, oldBlob, _ := redacted(t)
	if err := s.PurgeFromHistory(eng, fd, name, uAlice); !denied(err) {
		t.Fatalf("pentester: %v", err)
	}
	if err := s.PurgeFromHistory(eng, fd, name, uBob); !denied(err) {
		t.Fatalf("reviewer: %v", err)
	}
	if err := s.PurgeFromHistory(eng, fd, "../finding.md", uDora); err == nil {
		t.Fatal("a name outside attachments/ was purged")
	}
	if !hasBlob(dir, oldBlob) {
		t.Fatal("a refused purge removed the original")
	}
	if err := s.Archive(eng, uDora); err != nil {
		t.Fatal(err)
	}
	if err := s.PurgeFromHistory(eng, fd, name, uDora); !errors.Is(err, ErrArchived) {
		t.Fatalf("archived: %v", err)
	}
}

// D28, Review focus 3: the purge changes no finding's text, approval or
// sign-off; the current image is the same bytes.
func TestPurgeKeepsStateAndContent(t *testing.T) {
	s, dir, fd, name, _, _ := redacted(t)
	if err := s.Transition(eng, fd, workflow.Submit, "", uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Clear, "", uBob); err != nil {
		t.Fatal(err)
	}
	if err := s.Transition(eng, fd, workflow.Approve, "", uDora); err != nil {
		t.Fatal(err)
	}
	md := filepath.Join(dir, "engagements", eng, "findings", fd, "finding.md")
	img := filepath.Join(dir, "engagements", eng, "findings", fd, "attachments", name)
	mdBefore, _ := os.ReadFile(md)
	imgBefore, _ := os.ReadFile(img)
	stBefore, _ := s.DB().State(eng, "F-001")
	if err := s.PurgeFromHistory(eng, fd, name, uDora); err != nil {
		t.Fatal(err)
	}
	mdAfter, _ := os.ReadFile(md)
	imgAfter, _ := os.ReadFile(img)
	stAfter, _ := s.DB().State(eng, "F-001")
	if !bytes.Equal(mdBefore, mdAfter) || !bytes.Equal(imgBefore, imgAfter) {
		t.Fatal("the finding or its image changed")
	}
	if !reflect.DeepEqual(stBefore, stAfter) || stAfter.Status != "complete" {
		t.Fatalf("state %+v, was %+v", stAfter, stBefore)
	}
	if ref, err := s.Finding(eng, fd); err != nil || ref.F.Meta.Status != "complete" {
		t.Fatalf("finding after the purge: %v", err)
	}
}

// D28: the main repository's pointer follows the rewritten history.
func TestPurgeUpdatesMainPointer(t *testing.T) {
	s, dir, fd, name, _, _ := redacted(t)
	if err := s.PurgeFromHistory(eng, fd, name, uDora); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("git", "-C", dir, "ls-tree", "HEAD", "engagements/"+eng).Output()
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(out))
	if len(f) < 3 || f[2] != engGit(t, dir, "rev-parse", "HEAD") {
		t.Fatalf("main pointer %q, engagement HEAD %s", out, engGit(t, dir, "rev-parse", "HEAD"))
	}
}

// D28, Review focus 2: the purge holds the engagement's lock (a push holds
// it too), so it waits for whoever has it.
func TestPurgeWaitsForLock(t *testing.T) {
	s, _, fd, name, _, _ := redacted(t)
	unlock := s.LockEngagement(eng)
	done := make(chan error, 1)
	go func() { done <- s.PurgeFromHistory(eng, fd, name, uDora) }()
	select {
	case err := <-done:
		unlock()
		t.Fatalf("the purge ran under someone else's lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// D28, Review focus 4: a purge that fails half-way leaves the repository
// as it was.
func TestPurgeFailureLeavesRepo(t *testing.T) {
	s, dir, fd, name, oldBlob, _ := redacted(t)
	head0 := engGit(t, dir, "rev-parse", "HEAD")
	s.beforePurgeGC = func() error { return errors.New("disk full") }
	if err := s.PurgeFromHistory(eng, fd, name, uDora); err == nil {
		t.Fatal("the failure was not reported")
	}
	if h := engGit(t, dir, "rev-parse", "HEAD"); h != head0 {
		t.Fatalf("HEAD %s, was %s", h, head0)
	}
	if !hasBlob(dir, oldBlob) {
		t.Fatal("the original is gone after a failed purge")
	}
	if !hasOriginal(t, s, fd, name) {
		t.Fatal("the mark went with a failed purge")
	}
	if st := engGit(t, dir, "status", "--porcelain"); st != "" {
		t.Fatalf("work tree after a failed purge: %q", st)
	}
}
