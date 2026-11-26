package store

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/abno525/yars/internal/db"
)

// stepOf finds a rule's step in a status.
func stepOf(t *testing.T, st CheckStatus, rule string) db.CheckStep {
	t.Helper()
	for _, x := range st.Steps {
		if x.Rule == rule {
			return x
		}
	}
	t.Fatalf("no step %s in %+v", rule, st.Steps)
	return db.CheckStep{}
}

// A run records each rule: its kind, its state (pass, hits, failed) and
// when it started and ended.
func TestCheckSteps(t *testing.T) {
	s, dir, fd := ready(t)
	rd := filepath.Join(dir, ".yars", "rules")
	withRules(t, s, dir, checkRules+"- id: scr\n  script: x.sh\n")
	// fails until a file outside the rules folder exists, as a passing
	// failure does (editing a rule file makes the whole run out of date)
	ok := filepath.Join(dir, "scr-ok")
	os.WriteFile(filepath.Join(rd, "x.sh"), []byte("#!/bin/sh\ncat >/dev/null\nif [ -e "+ok+" ]; then echo '[]'; exit 0; fi\necho boom >&2\nexit 3\n"), 0o755)
	st := checked(t, s, fd)
	if len(st.Steps) != 3 || st.Steps[0].Rule != "no-sql" || st.Steps[2].Rule != "scr" {
		t.Fatalf("steps %+v", st.Steps)
	}
	if x := stepOf(t, st, "no-sql"); x.State != db.StepHits || x.Hits != 1 || x.Kind != "pattern" || x.Started == "" || x.Finished == "" {
		t.Fatalf("no-sql %+v", x)
	}
	if x := stepOf(t, st, "no-foo"); x.State != db.StepPass || x.Hits != 0 {
		t.Fatalf("no-foo %+v", x)
	}
	if x := stepOf(t, st, "scr"); x.State != db.StepFailed || x.Kind != "script" || !strings.Contains(x.Message, "boom") {
		t.Fatalf("scr %+v", x)
	}
	threads := checkThreads(t, s, fd)

	// Retry runs only the failed rule; the others keep their results
	os.WriteFile(ok, nil, 0o644)
	if _, err := s.RetryCheck(eng, fd, "scr", uAlice); err != nil {
		t.Fatal(err)
	}
	s.WaitChecks()
	again, err := s.CheckStatus(eng, fd)
	if err != nil {
		t.Fatal(err)
	}
	if again.Run.ID == st.Run.ID || again.Run.State != db.RunDone || len(again.Steps) != 3 {
		t.Fatalf("retry run %+v steps %+v", again.Run, again.Steps)
	}
	if x := stepOf(t, again, "scr"); x.State != db.StepPass {
		t.Fatalf("scr after retry %+v", x)
	}
	if x := stepOf(t, again, "no-sql"); x.State != db.StepHits || x.Started != stepOf(t, st, "no-sql").Started {
		t.Fatalf("no-sql after retry %+v", x)
	}
	if len(again.Results) != 1 || again.Results[0].Rule != "no-sql" {
		t.Fatalf("results after retry %+v", again.Results)
	}
	if th := checkThreads(t, s, fd); len(th) != len(threads) || th[""].Root.ID != threads[""].Root.ID || th[""].Resolved {
		t.Fatalf("threads after retry %+v", th)
	}
	if _, err := s.RetryCheck(eng, fd, "nope", uAlice); err == nil {
		t.Fatal("retried an unknown rule")
	}
}

// A dismissal keeps its reason, which is also the last word in the
// violation's thread before it is resolved.
func TestDismissReason(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules)
	checked(t, s, fd)
	const why = "SQL is in the client's glossary"
	if err := s.DismissWhy(eng, fd, "no-sql", "title", "SQL", why, uBob); err != nil {
		t.Fatal(err)
	}
	ds, _ := s.Dismissals(eng, load(t, s, fd).F.Meta.ID)
	if d := ds[db.DismissKey("no-sql", ViolationHash("title", "SQL"))]; d.Reason != why || d.By != "bob" {
		t.Fatalf("dismissal %+v", d)
	}
	th := checkThreads(t, s, fd)[""]
	if !th.Resolved || len(th.Replies) == 0 || th.Replies[len(th.Replies)-1].Text != why || th.Replies[len(th.Replies)-1].User != "bob" {
		t.Fatalf("thread %+v", th)
	}
}

// A dismissal that resolves the violation's threads tells the pages the
// chat changed, so a section's open-thread count follows (M34 review).
func TestDismissAnnouncesChat(t *testing.T) {
	s, dir, fd := ready(t)
	withRules(t, s, dir, checkRules)
	checked(t, s, fd)
	var kinds []string
	s.OnChange(func(c Change) { kinds = append(kinds, c.Kind) })
	if err := s.DismissWhy(eng, fd, "no-sql", "title", "SQL", "glossary", uBob); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(kinds, ChangeChat) {
		t.Fatalf("changes %v", kinds)
	}
}
