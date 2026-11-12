package store

import (
	"bytes"
	"errors"
	"fmt"
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
// it too), so it waits for whoever has it: it does not even rewrite.
func TestPurgeWaitsForLock(t *testing.T) {
	s, dir, fd, name, oldBlob, _ := redacted(t)
	head0 := engGit(t, dir, "rev-parse", "HEAD")
	rewritten := make(chan struct{})
	s.beforePurgeGC = func() error { close(rewritten); return nil }
	unlock := s.LockEngagement(eng)
	done := make(chan error, 1)
	go func() { done <- s.PurgeFromHistory(eng, fd, name, uDora) }()
	select {
	case <-rewritten:
		unlock()
		t.Fatal("the purge rewrote under someone else's lock")
	case err := <-done:
		unlock()
		t.Fatalf("the purge ended under someone else's lock: %v", err)
	case <-time.After(time.Second):
	}
	if h := engGit(t, dir, "rev-parse", "HEAD"); h != head0 || !hasBlob(dir, oldBlob) {
		unlock()
		t.Fatal("the history changed while the lock was held")
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// commitAs commits in the engagement's repository with git itself (merges
// the store does not make: a pushed history).
func commitAs(t *testing.T, dir string, args ...string) {
	t.Helper()
	engGit(t, dir, append([]string{"-c", "user.name=alice", "-c", "user.email=alice@yars.local"}, args...)...)
}

// D28: an image whose current version a merge made (a conflict resolved
// with a new file) keeps that version; every other one goes.
func TestPurgeKeepsMergeMadeImage(t *testing.T) {
	s, dir, fd, name, oldBlob, curBlob := redacted(t)
	p := "findings/" + fd + "/attachments/" + name
	file := filepath.Join(dir, "engagements", eng, p)
	main := engGit(t, dir, "rev-parse", "--abbrev-ref", "HEAD")
	put := func(c color.Color, msg string) string {
		t.Helper()
		if err := os.WriteFile(file, pngBytes(t, c), 0o644); err != nil {
			t.Fatal(err)
		}
		commitAs(t, dir, "commit", "-q", "-a", "-m", msg)
		return engGit(t, dir, "rev-parse", "HEAD:"+p)
	}
	commitAs(t, dir, "checkout", "-q", "-b", "side", "HEAD~1")
	sideBlob := put(color.Gray{Y: 128}, "side")
	commitAs(t, dir, "checkout", "-q", main)
	exec.Command("git", "-C", filepath.Join(dir, "engagements", eng), "-c", "user.name=alice", "-c", "user.email=alice@yars.local", "merge", "-q", "side").Run() // conflicts
	red := color.RGBA{R: 255, A: 255}
	mergeBlob := put(red, "resolved")
	commitAs(t, dir, "branch", "-q", "-D", "side")
	s.Invalidate(eng)
	if err := s.PurgeFromHistory(eng, fd, name, uDora); err != nil {
		t.Fatal(err)
	}
	if got := engGit(t, dir, "rev-parse", "HEAD:"+p); got != mergeBlob {
		t.Fatalf("current version %s, want %s", got, mergeBlob)
	}
	if b, _ := os.ReadFile(file); !bytes.Equal(b, pngBytes(t, red)) {
		t.Fatal("the image on disk changed")
	}
	for _, b := range []string{oldBlob, curBlob, sideBlob} {
		if hasBlob(dir, b) {
			t.Fatalf("version %s is still in history", b)
		}
	}
	if b, _ := s.DB().PurgedBlobs(eng); len(b) != 3 {
		t.Fatalf("purged blobs %v", b)
	}
}

// D28: the same bytes under another name keep the original in history; the
// purge says where and changes nothing.
func TestPurgeRefusedWhileCopyElsewhere(t *testing.T) {
	s, dir, fd, name, oldBlob, _ := redacted(t)
	if _, err := s.AddAttachment(eng, fd, "copy.png", pngBytes(t, color.White), uAlice); err != nil {
		t.Fatal(err)
	}
	head0 := engGit(t, dir, "rev-parse", "HEAD")
	err := s.PurgeFromHistory(eng, fd, name, uDora)
	if err == nil || !strings.Contains(err.Error(), "attachments/copy.png") {
		t.Fatalf("purge with a copy: %v", err)
	}
	if h := engGit(t, dir, "rev-parse", "HEAD"); h != head0 || !hasBlob(dir, oldBlob) {
		t.Fatal("a refused purge changed the history")
	}
	if !hasOriginal(t, s, fd, name) {
		t.Fatal("a refused purge took the mark")
	}
	if b, _ := s.DB().PurgedBlobs(eng); len(b) != 0 {
		t.Fatalf("a refused purge recorded %v", b)
	}
}

// D28: a copy of the original (Merge copies attachments; the same upload
// twice) is redacted first, as the refusal says; then the purge takes the
// original out at both names, and the copy's own Purge only clears its
// mark.
func TestPurgeAfterCopyRedacted(t *testing.T) {
	s, dir, fd, name, oldBlob, _ := redacted(t)
	cp, err := s.AddAttachment(eng, fd, "copy.png", pngBytes(t, color.White), uAlice)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PurgeFromHistory(eng, fd, name, uDora); err == nil || !strings.Contains(err.Error(), "attachments/copy.png; redact it there first") {
		t.Fatalf("purge with the copy unredacted: %v", err)
	}
	if err := s.ReplaceAttachment(eng, fd, cp, pngBytes(t, color.Gray{Y: 64}), uAlice); err != nil {
		t.Fatal(err)
	}
	if err := s.PurgeFromHistory(eng, fd, name, uDora); err != nil {
		t.Fatal(err)
	}
	if hasBlob(dir, oldBlob) {
		t.Fatal("the original is still in the repository")
	}
	if err := s.PurgeFromHistory(eng, fd, cp, uDora); err != nil {
		t.Fatal(err)
	}
	if hasOriginal(t, s, fd, cp) || hasOriginal(t, s, fd, name) {
		t.Fatal("still marked")
	}
}

// D28: a push renamed the finding's folder after the redaction: the
// original under the old folder name is found and purged.
func TestPurgeAfterFolderRenamed(t *testing.T) {
	s, dir, fd, name, oldBlob, _ := redacted(t)
	commitAs(t, dir, "mv", "findings/"+fd, "findings/F-001-renamed")
	commitAs(t, dir, "commit", "-q", "-m", "renamed")
	s.Invalidate(eng)
	if err := s.PurgeFromHistory(eng, "F-001-renamed", name, uDora); err != nil {
		t.Fatal(err)
	}
	if hasBlob(dir, oldBlob) {
		t.Fatal("the original is still in the repository")
	}
	if b, _ := s.DB().PurgedBlobs(eng); b[oldBlob] != name {
		t.Fatalf("purged blobs %v", b)
	}
	if hasOriginal(t, s, "F-001-renamed", name) {
		t.Fatal("still marked")
	}
}

// D28: a purge the server stopped after the rewrite (backup ref, reflogs
// and the original still there): Purge again removes them before the mark
// goes.
func TestPurgeFinishesInterruptedRewrite(t *testing.T) {
	s, dir, fd, name, oldBlob, _ := redacted(t)
	p := "findings/" + fd + "/attachments/" + name
	if _, err := s.DB().AddPurgedBlobs(eng, name, []string{oldBlob}); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-C", filepath.Join(dir, "engagements", eng), "filter-branch", "-f", "--index-filter",
		`test "$(git rev-parse -q --verify :`+p+`)" = "`+oldBlob+`" && git rm -q --cached -- `+p+`; true`, "--", "HEAD")
	cmd.Env = append(os.Environ(), "FILTER_BRANCH_SQUELCH_WARNING=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("filter-branch: %v %s", err, out)
	}
	s.Invalidate(eng)
	if err := s.PurgeFromHistory(eng, fd, name, uDora); err != nil {
		t.Fatal(err)
	}
	if refs := engGit(t, dir, "for-each-ref", "refs/original"); refs != "" || hasBlob(dir, oldBlob) {
		t.Fatalf("backup refs %q, original on disk %v", refs, hasBlob(dir, oldBlob))
	}
	if hasOriginal(t, s, fd, name) {
		t.Fatal("still marked")
	}
}

// D28: a gc that stops before it removes anything (another gc running, a
// full disk) leaves the original on disk: the mark stays, and Purge again
// runs the cleanup.
func TestPurgeRetryFinishesCleanup(t *testing.T) {
	s, dir, fd, name, oldBlob, _ := redacted(t)
	host, _ := os.Hostname()
	pid := filepath.Join(dir, "engagements", eng, ".git", "gc.pid")
	if err := os.WriteFile(pid, []byte(fmt.Sprintf("%d %s", os.Getpid(), host)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.PurgeFromHistory(eng, fd, name, uDora); !errors.Is(err, ErrPurgeIncomplete) {
		t.Fatalf("gc refused: %v", err)
	}
	if !hasBlob(dir, oldBlob) {
		t.Skip("this git's gc ignores gc.pid")
	}
	if !hasOriginal(t, s, fd, name) {
		t.Fatal("the mark went while the original is still on disk")
	}
	os.Remove(pid)
	if err := s.PurgeFromHistory(eng, fd, name, uDora); err != nil {
		t.Fatal(err)
	}
	if hasBlob(dir, oldBlob) || hasOriginal(t, s, fd, name) {
		t.Fatalf("after the retry: on disk %v, marked %v", hasBlob(dir, oldBlob), hasOriginal(t, s, fd, name))
	}
}

// D28: a gc that fails comes after the point of no return: the purge is
// recorded, audited and the main repository follows; the error says the
// cleanup failed, and the mark stays until a Purge again finishes it.
func TestPurgeCleanupFailureStillRecorded(t *testing.T) {
	s, dir, fd, name, oldBlob, _ := redacted(t)
	lock := filepath.Join(dir, "engagements", eng, ".git", "objects", "info", "commit-graph.lock")
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err := s.PurgeFromHistory(eng, fd, name, uDora)
	if !errors.Is(err, ErrPurgeIncomplete) || !strings.Contains(err.Error(), "cleanup failed") {
		t.Fatalf("gc failure: %v", err)
	}
	if !hasOriginal(t, s, fd, name) {
		t.Fatal("the mark went before the cleanup")
	}
	if b, _ := s.DB().PurgedBlobs(eng); b[oldBlob] != name {
		t.Fatalf("purged blobs %v", b)
	}
	if l, _ := s.DB().AuditLog(1); len(l) != 1 || l[0].Action != "attachment.purge" {
		t.Fatalf("audit %+v", l)
	}
	out, _ := exec.Command("git", "-C", dir, "ls-tree", "HEAD", "engagements/"+eng).Output()
	if f := strings.Fields(string(out)); len(f) < 3 || f[2] != engGit(t, dir, "rev-parse", "HEAD") {
		t.Fatalf("main pointer %q", out)
	}
	// Purge again finishes it
	os.Remove(lock)
	if err := s.PurgeFromHistory(eng, fd, name, uDora); err != nil {
		t.Fatal(err)
	}
	if hasOriginal(t, s, fd, name) {
		t.Fatal("still marked after Purge again")
	}
}

// D28: a purge git refuses (an uncommitted change) leaves that change.
func TestPurgeRefusedKeepsWorkTree(t *testing.T) {
	s, dir, fd, name, _, _ := redacted(t)
	md := filepath.Join(dir, "engagements", eng, "findings", fd, "finding.md")
	b, _ := os.ReadFile(md)
	changed := append(b, []byte("\nnot committed\n")...)
	if err := os.WriteFile(md, changed, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.PurgeFromHistory(eng, fd, name, uDora); err == nil {
		t.Fatal("purged with an uncommitted change")
	}
	if got, _ := os.ReadFile(md); !bytes.Equal(got, changed) {
		t.Fatal("the uncommitted change is gone")
	}
}

// D28: the finding may be named as Finding accepts it (its ID).
func TestPurgeByFindingID(t *testing.T) {
	s, dir, _, name, oldBlob, _ := redacted(t)
	if err := s.PurgeFromHistory(eng, "F-001", name, uDora); err != nil {
		t.Fatal(err)
	}
	if hasBlob(dir, oldBlob) {
		t.Fatal("the original is still there")
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
	if b, _ := s.DB().PurgedBlobs(eng); len(b) != 0 {
		t.Fatalf("a failed purge left blob ids %v", b)
	}
}

// D28: the removed blob ids are known before the history is rewritten, so
// no failure after it can lose them.
func TestPurgeRemembersBlobsFirst(t *testing.T) {
	s, _, fd, name, oldBlob, _ := redacted(t)
	var seen map[string]string
	s.beforePurgeGC = func() error { seen, _ = s.DB().PurgedBlobs(eng); return nil }
	if err := s.PurgeFromHistory(eng, fd, name, uDora); err != nil {
		t.Fatal(err)
	}
	if seen[oldBlob] != name {
		t.Fatalf("before gc the purged blobs were %v", seen)
	}
}
