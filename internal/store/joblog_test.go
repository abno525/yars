package store

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/rules"
)

// A wait for a repository's lock over the threshold is one warn line with
// the engagement and the time, written once the lock is taken; a lock that
// is free writes none. While it is held and waited for, LockStates says so.
func TestLongLockWaitIsLogged(t *testing.T) {
	s, _ := withEngagement(t)
	lg, out := logs.NewRecorder()
	s.Logger = lg
	s.lockWarn = 20 * time.Millisecond
	const msg = "lock: a long wait for a repository's lock"

	s.LockEngagement(eng)()
	s.LockMain()()
	if recs := out.With(msg); len(recs) != 0 {
		t.Fatalf("a free lock is logged:\n%s", out.Text())
	}
	if st := s.LockStates(); len(st) != 0 {
		t.Fatalf("free locks are listed: %+v", st)
	}

	// held is called with the lock held and a second taker started: it waits
	// until LockStates shows both, then past the threshold
	held := func(name string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			st := s.LockStates()
			if len(st) == 1 && st[0].Eng == name && st[0].Held > 0 && st[0].Waiting == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the held lock and its waiter are not listed: %+v", st)
			}
			time.Sleep(time.Millisecond)
		}
		time.Sleep(40 * time.Millisecond)
	}
	unlock := s.LockEngagement(eng)
	done := make(chan struct{})
	go func() {
		s.LockEngagement(eng)()
		done <- struct{}{}
	}()
	held(eng)
	unlock()
	<-done
	recs := out.With(msg)
	if len(recs) != 1 || recs[0].Level != slog.LevelWarn || recs[0].Str("eng") != eng || !recs[0].Has("ms") {
		t.Fatalf("log:\n%s", out.Text())
	}
	if ms, _ := recs[0].Attrs["ms"].(int64); ms < 20 {
		t.Fatalf("ms %v", recs[0].Attrs["ms"])
	}

	// the main repo's lock is named as such
	out.Reset()
	unlock = s.LockMain()
	go func() {
		s.LockMain()()
		done <- struct{}{}
	}()
	held("")
	unlock()
	<-done
	if recs := out.With(msg); len(recs) != 1 || recs[0].Str("repo") != "main" || recs[0].Has("eng") {
		t.Fatalf("main lock:\n%s", out.Text())
	}
}

// panicLinter crashes in a full check.
type panicLinter struct{}

func (panicLinter) Lint(_ context.Context, _ *finding.Finding, k rules.Kind) []rules.Violation {
	if k == rules.All {
		panic("zqpanic7f3kq")
	}
	return nil
}

// A check run writes one info line when it ends: the engagement, the
// finding's ID, who asked, its state, the counts and the time. A run that
// crashes writes an error line too, and a run dropped at a stop its own
// line. None names the finding's folder (it holds the title).
func TestCheckRunEndIsLogged(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules)
	lg, out := logs.NewRecorder()
	s.Logger = lg
	checked(t, s, fd)
	recs := out.With("check run finished")
	if len(recs) != 1 {
		t.Fatalf("log:\n%s", out.Text())
	}
	r := recs[0]
	if r.Level != slog.LevelInfo || r.Str("eng") != eng || r.Str("finding") != "F-001" || r.Str("user") != "alice" ||
		r.Str("state") != "done" || r.Str("errors") != "1" || r.Str("warnings") != "0" || !r.Has("ms") {
		t.Fatalf("line: %s", r)
	}
	if slug := strings.TrimPrefix(fd, "F-001"); slug == "" || strings.Contains(out.Text(), slug) {
		t.Fatalf("the log names the folder %s:\n%s", fd, out.Text())
	}

	// a crash: an error line, and the end line says failed
	out.Reset()
	keep := s.Linter
	s.Linter = panicLinter{}
	checked(t, s, fd)
	crashed := out.With("check run crashed")
	if len(crashed) != 1 || crashed[0].Level != slog.LevelError || crashed[0].Str("eng") != eng || crashed[0].Str("finding") != "F-001" ||
		crashed[0].Str("user") != "alice" || !strings.Contains(crashed[0].Str("err"), "zqpanic7f3kq") {
		t.Fatalf("crash log:\n%s", out.Text())
	}
	if recs := out.With("check run finished"); len(recs) != 1 || recs[0].Str("state") != "failed" {
		t.Fatalf("end line after a crash:\n%s", out.Text())
	}

	// a run dropped at a stop has its line too
	out.Reset()
	s.Linter = keep
	s.StopChecks()
	if _, err := s.StartCheck(eng, fd, uAlice); err != nil {
		t.Fatal(err)
	}
	s.WaitChecks()
	if recs := out.With("check run dropped"); len(recs) != 1 || recs[0].Str("eng") != eng || recs[0].Str("finding") != "F-001" ||
		recs[0].Str("user") != "alice" || recs[0].Str("outcome") != "interrupted" {
		t.Fatalf("dropped run:\n%s", out.Text())
	}
}

// A push writes one info line: accepted when the branch moved, refused when
// it did not, with the engagement (or the main repo), the account and the
// time.
func TestPushIsLogged(t *testing.T) {
	s, dir, fd := ready(t)
	lg, out := logs.NewRecorder()
	s.Logger = lg
	ed := filepath.Join(dir, "engagements", eng)
	s.ReceivePush(eng, uBob, func() {})
	recs := out.With("push refused")
	if len(recs) != 1 || recs[0].Level != slog.LevelInfo || recs[0].Str("eng") != eng || recs[0].Str("user") != "bob" || !recs[0].Has("ms") {
		t.Fatalf("a push that moved nothing:\n%s", out.Text())
	}
	out.Reset()
	s.ReceivePush(eng, uBob, func() {
		git(t, ed, "commit", "-q", "--allow-empty", "-m", "pushed zqcommit7f3kq")
	})
	if recs := out.With("push accepted"); len(recs) != 1 || recs[0].Level != slog.LevelInfo || recs[0].Str("eng") != eng || recs[0].Str("user") != "bob" ||
		!recs[0].Has("ms") || len(out.With("push refused")) != 0 {
		t.Fatalf("a push that moved the branch:\n%s", out.Text())
	}
	if strings.Contains(out.Text(), "zqcommit7f3kq") || strings.Contains(out.Text(), strings.TrimPrefix(fd, "F-001")) {
		t.Fatalf("the log holds text:\n%s", out.Text())
	}
	out.Reset()
	s.ReceivePush("", uBob, func() {})
	if recs := out.With("push refused"); len(recs) != 1 || recs[0].Str("repo") != "main" || recs[0].Has("eng") || recs[0].Str("user") != "bob" {
		t.Fatalf("a push to the main repo:\n%s", out.Text())
	}
}
