package db

import (
	"strconv"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
)

// at is a stored time, as the database writes it.
func at(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func count(t *testing.T, d *DB, table string) int {
	t.Helper()
	var n int
	if err := d.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// D24: without settings, the audit log is kept for good, check runs 90
// days, sessions 14.
func TestRetentionDefaults(t *testing.T) {
	d, _ := open(t)
	if r, err := d.Retention(); err != nil || r != (Retention{AuditDays: 0, CheckRunDays: 90, SessionDays: 14}) {
		t.Fatalf("defaults %+v %v", r, err)
	}
	if err := d.SetRetention(Retention{AuditDays: 365, CheckRunDays: 0, SessionDays: 7}); err != nil {
		t.Fatal(err)
	}
	if r, _ := d.Retention(); r != (Retention{AuditDays: 365, CheckRunDays: 0, SessionDays: 7}) {
		t.Fatalf("stored %+v", r)
	}
	for _, bad := range []Retention{{AuditDays: -1}, {CheckRunDays: 3651}, {SessionDays: 4000}} {
		if err := d.SetRetention(bad); err == nil {
			t.Errorf("%+v stored", bad)
		}
	}
	if r, _ := d.Retention(); r.AuditDays != 365 {
		t.Fatalf("a refused value changed the settings: %+v", r)
	}
}

// oldRuns adds n finished runs of one finding, all a year old, and returns
// their ids, oldest first.
func oldRuns(t *testing.T, d *DB, fid string, n int) []int64 {
	t.Helper()
	var ids []int64
	for i := range n {
		id, err := d.StartRun("acme", fid, "h", "bob", "")
		if err != nil {
			t.Fatal(err)
		}
		if err := d.TxFor("acme", func(tx *Tx) error {
			return tx.FinishRun(id, RunDone, "", []CheckResult{{Rule: "r", Level: "error", QuoteHash: strconv.Itoa(i)}})
		}); err != nil {
			t.Fatal(err)
		}
		d.AddSteps([]CheckStep{{RunID: id, Pos: 0, Rule: "r", Kind: "pattern", State: StepHits, Hits: 1}})
		ids = append(ids, id)
	}
	year := at(time.Now().AddDate(-1, 0, 0))
	if _, err := d.Exec("UPDATE check_runs SET started = ?, finished = ? WHERE fid = ?", year, year, fid); err != nil {
		t.Fatal(err)
	}
	return ids
}

// D24, Review focus 1: the latest run of a finding is never deleted (the
// Require Check gate reads it); older ones go with their results and steps.
func TestPruneKeepsLatestRun(t *testing.T) {
	d, _ := open(t)
	ids := oldRuns(t, d, "F-001", 3)
	// the finding was edited between the runs (runs on the newest run's
	// content stay: TestPruneKeepsRunsOnTheLatestContent)
	d.Exec("UPDATE check_runs SET content_hash = 'earlier' WHERE id IN (?, ?)", ids[0], ids[1])
	other := oldRuns(t, d, "F-002", 1)
	p, err := d.Prune(time.Now(), Retention{CheckRunDays: 90})
	if err != nil || p != (Pruned{CheckRuns: 2}) {
		t.Fatalf("pruned %+v %v", p, err)
	}
	for _, id := range ids[:2] {
		if _, err := d.Run(id); err == nil {
			t.Errorf("run %d kept", id)
		}
		if res, _ := d.RunResults(id); len(res) != 0 {
			t.Errorf("results of run %d kept", id)
		}
		if st, _ := d.RunSteps(id); len(st) != 0 {
			t.Errorf("steps of run %d kept", id)
		}
	}
	for _, id := range []int64{ids[2], other[0]} {
		if _, err := d.Run(id); err != nil {
			t.Errorf("latest run %d deleted: %v", id, err)
		}
		if res, _ := d.RunResults(id); len(res) != 1 {
			t.Errorf("results of the latest run %d: %d", id, len(res))
		}
	}
	// a run still going is never deleted either (it has not finished), even
	// when it is neither the newest nor on the newest run's content
	going, _ := d.StartRun("acme", "F-003", "old", "bob", "")
	d.Exec("UPDATE check_runs SET started = ? WHERE id = ?", at(time.Now().AddDate(-1, 0, 0)), going)
	newer, _ := d.StartRun("acme", "F-003", "new", "bob", "")
	d.TxFor("acme", func(tx *Tx) error { return tx.FinishRun(newer, RunDone, "", nil) })
	if _, err := d.Prune(time.Now(), Retention{CheckRunDays: 90}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Run(going); err != nil {
		t.Fatal("a running run was deleted")
	}
}

// D24: the runs on the content of a finding's newest run stay too, however
// old: the open checks read them for rules that failed in the newest run
// (or all of them when it was cut off), and their results hold the chat
// threads of open violations. Runs on older content go.
func TestPruneKeepsRunsOnTheLatestContent(t *testing.T) {
	d, _ := open(t)
	old := oldRuns(t, d, "F-001", 2) // content "h", a year old
	d.Exec("UPDATE check_runs SET content_hash = 'before' WHERE id = ?", old[0])
	cut, _ := d.StartRun("acme", "F-001", "h", "bob", "")
	if err := d.FailRun(cut, "crashed"); err != nil { // the newest run: cut off, no results
		t.Fatal(err)
	}
	p, err := d.Prune(time.Now(), Retention{CheckRunDays: 90})
	if err != nil || p.CheckRuns != 1 {
		t.Fatalf("pruned %+v %v", p, err)
	}
	if _, err := d.Run(old[0]); err == nil {
		t.Error("a run on older content was kept")
	}
	if res, _ := d.RunResults(old[1]); len(res) != 1 {
		t.Error("the run on the newest run's content lost its results")
	}
}

// D24, Review focus 2: 0 keeps the audit log and the check runs for good.
// Sessions are not kept for good: one unused for a year is dead at 0 too
// (the default idle time), and its row goes; one in use stays.
func TestPruneZeroKeepsAll(t *testing.T) {
	d, _ := open(t)
	oldRuns(t, d, "F-001", 3)
	d.Audit("dora", "x", "", "")
	d.Exec("UPDATE audit SET ts = ?", at(time.Now().AddDate(-5, 0, 0)))
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	d.CreateSession("s1", "bob")
	d.Exec("UPDATE sessions SET last_seen = ?", at(time.Now().AddDate(-1, 0, 0)))
	d.CreateSession("s2", "bob")
	audit, runs, sessions := count(t, d, "audit"), count(t, d, "check_runs"), count(t, d, "sessions")
	if p, err := d.Prune(time.Now(), Retention{}); err != nil || p != (Pruned{Sessions: 1}) {
		t.Fatalf("pruned %+v %v", p, err)
	}
	if count(t, d, "audit") != audit || count(t, d, "check_runs") != runs || count(t, d, "sessions") != sessions-1 {
		t.Fatal("Retention{} deleted something")
	}
}

// D24: audit entries and sessions older than the cutoff go, newer ones stay.
func TestPruneAuditAndSessions(t *testing.T) {
	d, _ := open(t)
	now := time.Now()
	d.Audit("dora", "old", "", "")
	d.Exec("UPDATE audit SET ts = ? WHERE action = 'old'", at(now.AddDate(0, 0, -31)))
	d.Audit("dora", "new", "", "")
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	d.CreateSession("old", "bob")
	d.CreateSession("new", "bob")
	d.Exec("UPDATE sessions SET last_seen = ? WHERE hash = 'old'", at(now.AddDate(0, 0, -15)))
	p, err := d.Prune(now, Retention{AuditDays: 30, SessionDays: 14})
	if err != nil || p != (Pruned{Audit: 1, Sessions: 1}) {
		t.Fatalf("pruned %+v %v", p, err)
	}
	if l, _ := d.AuditLog(10); len(l) != 1 || l[0].Action != "new" {
		t.Fatalf("audit left %+v", l)
	}
	if ss, _ := d.Sessions(); len(ss) != 1 {
		t.Fatalf("sessions left %+v", ss)
	}
}

// Q1 review: stored rule results (quotes of finding text) go with the check
// runs' retention, by when they were stored; 0 keeps them.
func TestPruneRuleResults(t *testing.T) {
	d, _ := open(t)
	now := time.Now()
	d.PutRuleResult("old", "ai", "{}")
	d.PutRuleResult("new", "script", "[]")
	d.Exec("UPDATE rule_cache SET created = ? WHERE key = 'old'", now.AddDate(0, 0, -91).Unix())
	if p, err := d.Prune(now, Retention{}); err != nil || p != (Pruned{}) || count(t, d, "rule_cache") != 2 {
		t.Fatalf("Retention{} pruned %+v %v", p, err)
	}
	p, err := d.Prune(now, Retention{CheckRunDays: 90})
	if err != nil || p != (Pruned{RuleResults: 1}) {
		t.Fatalf("pruned %+v %v", p, err)
	}
	if _, ok, _ := d.RuleResult("old"); ok {
		t.Fatal("a result older than the check runs' days was kept")
	}
	if _, ok, _ := d.RuleResult("new"); !ok {
		t.Fatal("a new result was deleted")
	}
}

// D24: a session idle longer than the retention's session days is refused.
func TestSessionIdleFollowsRetention(t *testing.T) {
	d, _ := open(t)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	if err := d.SetRetention(Retention{SessionDays: 1}); err != nil {
		t.Fatal(err)
	}
	d.CreateSession("s1", "bob")
	now = now.Add(2 * 24 * time.Hour)
	if _, ok, _ := d.SessionUser("s1"); ok {
		t.Fatal("a session idle for two days is valid with SessionDays 1")
	}
	// 0 keeps the built-in limit
	d.SetRetention(Retention{SessionDays: 0})
	d.CreateSession("s2", "bob")
	now = now.Add(13 * 24 * time.Hour)
	if _, ok, _ := d.SessionUser("s2"); !ok {
		t.Fatal("SessionDays 0 does not fall back to SessionIdle")
	}
}
