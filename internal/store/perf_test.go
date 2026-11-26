package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abno525/yars/internal/chat"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/workflow"
)

// spawns counts git processes started by fn.
func spawns(fn func()) int64 {
	n := gitrepo.Spawned()
	fn()
	return gitrepo.Spawned() - n
}

// Version and listings start no git process, warm or cold.
func TestVersionStartsNoGit(t *testing.T) {
	s, dir := withEngagement(t)
	s.CreateFinding(eng, "SQLi", alice)
	if n := spawns(func() { s.Version() }); n != 0 {
		t.Fatalf("warm Version: %d git processes", n)
	}
	if n := spawns(func() { s.ListFindings(eng); s.ListEngagements() }); n != 0 {
		t.Fatalf("listing: %d git processes", n)
	}
	cold := New(s.Repo(), config.Default(), s.DB())
	var v string
	if n := spawns(func() { v, _ = cold.Version() }); n != 0 {
		t.Fatalf("cold Version: %d git processes", n)
	}
	if want, _ := s.Version(); v != want {
		t.Fatalf("cold %q warm %q", v, want)
	}
	if h := git(t, filepath.Join(dir, "engagements", eng), "rev-parse", "HEAD"); !contains(v, eng+"="+h) {
		t.Fatalf("version %q lacks %s", v, h)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// Our own commits move the version at once.
func TestVersionFollowsOwnCommits(t *testing.T) {
	s, _ := withEngagement(t)
	v0, _ := s.Version()
	f, _ := s.CreateFinding(eng, "SQLi", alice)
	v1, _ := s.Version()
	if v1 == v0 {
		t.Fatal("create not seen")
	}
	s.UpdateSection(eng, f.Dir, "Impact", "x", "", alice)
	v2, _ := s.Version()
	if v2 == v1 {
		t.Fatal("edit not seen")
	}
	s.CreateEngagement(Engagement{ID: "beta", Name: "B"}, alice)
	if v3, _ := s.Version(); v3 == v2 || !contains(v3, "beta=") {
		t.Fatalf("new engagement not seen: %q", v3)
	}
}

// A commit made outside the store (a push) shows after Invalidate.
func TestInvalidate(t *testing.T) {
	s, dir := withEngagement(t)
	s.Version()
	ed := filepath.Join(dir, "engagements", eng)
	os.WriteFile(filepath.Join(ed, "notes.txt"), []byte("x"), 0o644)
	git(t, ed, "add", "notes.txt")
	git(t, ed, "-c", "user.name=x", "-c", "user.email=x@x", "commit", "-qm", "push")
	h := git(t, ed, "rev-parse", "HEAD")
	if v, _ := s.Version(); contains(v, h) {
		t.Fatal("cache not used")
	}
	s.Invalidate(eng)
	if v, _ := s.Version(); !contains(v, eng+"="+h) {
		t.Fatalf("version %q after invalidate", v)
	}
	// the push guard still reads the real HEAD
	f, err := s.CreateFinding(eng, "after push", alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateSection(eng, f.Dir, "Impact", "y", "", alice); err != nil {
		t.Fatal(err)
	}
}

// A sync with nothing to move starts no git process.
func TestSyncPointersWarmStartsNoGit(t *testing.T) {
	s, dir := withEngagement(t)
	s.CreateFinding(eng, "SQLi", alice)
	if err := s.SyncPointers(); err != nil {
		t.Fatal(err)
	}
	if n := spawns(func() { s.SyncPointers() }); n != 0 {
		t.Fatalf("%d git processes", n)
	}
	s.CreateFinding(eng, "XSS", alice)
	if err := s.SyncPointers(); err != nil {
		t.Fatal(err)
	}
	if link := git(t, dir, "rev-parse", "HEAD:engagements/"+eng); link != git(t, filepath.Join(dir, "engagements", eng), "rev-parse", "HEAD") {
		t.Fatal("pointer not moved")
	}
}

// Chat, transitions and reviewer changes don't wait for git work on the
// engagement (they are database writes only).
func TestDBWritesTakeNoGitLock(t *testing.T) {
	s, _ := withEngagement(t)
	f, _ := s.CreateFinding(eng, "SQLi", alice)
	s.UpdateSeverity(eng, f.Dir, "high", "", alice)
	l := s.engLock(eng)
	l.Lock()
	defer l.Unlock()
	s.mainMu.Lock()
	defer s.mainMu.Unlock()
	done := make(chan error, 1)
	go func() {
		if _, err := s.PostChat(eng, f.Dir, chat.Message{Text: "hi"}, uBob); err != nil {
			done <- err
			return
		}
		if err := s.SetReviewers(eng, f.Dir, []string{"bob"}, uAlice); err != nil {
			done <- err
			return
		}
		done <- s.Transition(eng, f.Dir, workflow.Submit, "", uAlice)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("database writes blocked by the git locks")
	}
}

// Engagements don't wait for each other.
func TestEngagementsLockSeparately(t *testing.T) {
	s, _ := withEngagement(t)
	s.CreateEngagement(Engagement{ID: "beta", Name: "B"}, alice)
	l := s.engLock(eng)
	l.Lock()
	defer l.Unlock()
	done := make(chan error, 1)
	go func() { _, err := s.CreateFinding("beta", "x", alice); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("beta waited for acme")
	}
}

// Database writes report which finding changed, with the engagement's new
// change counter.
func TestOnChange(t *testing.T) {
	s, _ := withEngagement(t)
	f, _ := s.CreateFinding(eng, "SQLi", alice)
	var mu sync.Mutex
	var got []Change
	s.OnChange(func(c Change) { mu.Lock(); got = append(got, c); mu.Unlock() })
	s.PostChat(eng, f.Dir, chat.Message{Text: "hi"}, uBob)
	s.SetReviewers(eng, f.Dir, []string{"bob"}, uAlice)
	seq, _ := s.DB().SeqFor(eng)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[0].Eng != eng || got[0].Fid != "F-001" || got[1].Seq != seq || got[0].Seq != seq-1 {
		t.Fatalf("changes %+v (seq %d)", got, seq)
	}
}

// ChatOf reads a loaded finding's chat.
func TestChatOf(t *testing.T) {
	s, _ := withEngagement(t)
	f, _ := s.CreateFinding(eng, "SQLi", alice)
	s.PostChat(eng, f.Dir, chat.Message{Text: "hi"}, uBob)
	ref, _ := s.Finding(eng, f.Dir)
	msgs, err := s.ChatOf(ref)
	if err != nil || len(msgs) != 1 || msgs[0].Text != "hi" {
		t.Fatalf("msgs %+v %v", msgs, err)
	}
}

// Concurrent content edits, chat, transitions and syncs across engagements
// (run with -race): every edit lands and every repo stays clean.
func TestConcurrentWrites(t *testing.T) {
	s, dir := withEngagement(t)
	s.CreateEngagement(Engagement{ID: "beta", Name: "B"}, alice)
	var dirs [][2]string
	for _, e := range []string{eng, "beta"} {
		for i := 0; i < 3; i++ {
			f, err := s.CreateFinding(e, fmt.Sprint("F ", i), alice)
			if err != nil {
				t.Fatal(err)
			}
			dirs = append(dirs, [2]string{e, f.Dir})
		}
	}
	var wg sync.WaitGroup
	for i, d := range dirs {
		wg.Add(3)
		go func() {
			defer wg.Done()
			for k := 0; k < 3; k++ {
				if err := s.UpdateSection(d[0], d[1], "Impact", fmt.Sprint("v", i, k), "", alice); err != nil {
					t.Error(err)
				}
			}
		}()
		go func() {
			defer wg.Done()
			for k := 0; k < 3; k++ {
				if _, err := s.PostChat(d[0], d[1], chat.Message{Text: fmt.Sprint("m", k)}, uBob); err != nil {
					t.Error(err)
				}
			}
			if err := s.SetReviewers(d[0], d[1], []string{"bob"}, uAlice); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			s.Version()
			s.ListFindings(d[0])
			if err := s.SyncPointers(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for i, d := range dirs {
		ref, _ := s.Finding(d[0], d[1])
		if body, _ := ref.F.Section("Impact"); strings.TrimSpace(body) != fmt.Sprint("v", i, 2) {
			t.Fatalf("%s/%s impact %q", d[0], d[1], body)
		}
		if msgs, _ := s.ChatOf(ref); len(msgs) != 3 {
			t.Fatalf("%d messages", len(msgs))
		}
	}
	for _, d := range []string{dir, filepath.Join(dir, "engagements", eng), filepath.Join(dir, "engagements", "beta")} {
		if st := git(t, d, "status", "--porcelain"); st != "" {
			t.Fatalf("%s dirty:\n%s", d, st)
		}
	}
	if err := s.SyncPointers(); err != nil {
		t.Fatal(err)
	}
	for _, e := range []string{eng, "beta"} {
		if link := git(t, dir, "rev-parse", "HEAD:engagements/"+e); link != git(t, filepath.Join(dir, "engagements", e), "rev-parse", "HEAD") {
			t.Fatalf("%s pointer behind", e)
		}
	}
}
