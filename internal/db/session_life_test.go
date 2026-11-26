package db

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/config"
)

// A session ends SessionMax after its login however much it is used, for
// the reading check too; the time it has left is the shorter of the idle
// time and what is left of SessionMax.
func TestSessionHasAnAbsoluteLimit(t *testing.T) {
	d, _ := open(t)
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	if err := d.SetRetention(Retention{SessionDays: 3}); err != nil {
		t.Fatal(err)
	}
	d.CreateSession("s1", "bob")
	if left := d.SessionLeft("s1"); left != 3*24*time.Hour {
		t.Fatalf("a new session has %s left, want the 3 idle days", left)
	}
	day := 24 * time.Hour
	for used := day; used < SessionMax; used += day {
		now = now.Add(day)
		if _, ok, _ := d.SessionUser("s1"); !ok {
			t.Fatalf("a session used every day ended after %s", used)
		}
	}
	// one day before the limit: that day is all it has left
	if left := d.SessionLeft("s1"); left != day {
		t.Fatalf("%s left one day before the limit, want %s", left, day)
	}
	now = now.Add(day + time.Minute)
	if _, ok, _ := d.SessionAlive("s1"); ok {
		t.Fatalf("a session is alive %s after its login", SessionMax+time.Minute)
	}
	if _, ok, _ := d.SessionUser("s1"); ok {
		t.Fatalf("a session used every day is good %s after its login", SessionMax+time.Minute)
	}
	if n := count(t, d, "sessions"); n != 0 {
		t.Fatalf("%d session rows after the refusal", n)
	}
	// unused for longer than the idle days: refused, as before
	d.CreateSession("s2", "bob")
	now = now.Add(4 * day)
	if _, ok, _ := d.SessionUser("s2"); ok {
		t.Fatal("a session unused for 4 days is good with 3 session days")
	}
	// no session by that name: the idle time (what a new one would have)
	if left := d.SessionLeft("none"); left != 3*day {
		t.Fatalf("no session: %s", left)
	}
}

// The deploy guide states the two limits as the code has them.
func TestDeployGuideStatesSessionLimits(t *testing.T) {
	b, err := os.ReadFile("../../docs/deploy.md")
	if err != nil {
		t.Fatal(err)
	}
	days := func(d time.Duration) int { return int(d / (24 * time.Hour)) }
	want := fmt.Sprintf("%d by default, and 0 means %d too. It ends %d days after the login at the latest", days(SessionIdle), days(SessionIdle), days(SessionMax))
	if !strings.Contains(string(b), want) {
		t.Fatalf("docs/deploy.md lacks %q", want)
	}
	d, _ := open(t)
	if r, _ := d.Retention(); r.SessionDays != days(SessionIdle) {
		t.Fatalf("the default session days %d are not SessionIdle", r.SessionDays)
	}
}

// At 0 session days a session is idle after the default 14 days, and Prune
// deletes its row then; it deletes a session past the absolute limit
// whatever the days are.
func TestPruneSessionsAtZeroAndPastTheLimit(t *testing.T) {
	d, _ := open(t)
	now := time.Now()
	d.AddUser(config.User{Username: "bob", Role: "reviewer"})
	for _, h := range []string{"idle15", "idle13", "old", "new"} {
		d.CreateSession(h, "bob")
	}
	d.Exec("UPDATE sessions SET last_seen = ? WHERE hash = 'idle15'", at(now.AddDate(0, 0, -15)))
	d.Exec("UPDATE sessions SET last_seen = ? WHERE hash = 'idle13'", at(now.AddDate(0, 0, -13)))
	d.Exec("UPDATE sessions SET created = ? WHERE hash = 'old'", at(now.Add(-SessionMax-time.Hour)))
	p, err := d.Prune(now, Retention{SessionDays: 0})
	if err != nil || p.Sessions != 2 {
		t.Fatalf("pruned %+v %v", p, err)
	}
	left := map[string]bool{}
	rows, err := d.Query("SELECT hash FROM sessions")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var h string
		rows.Scan(&h)
		left[h] = true
	}
	rows.Close()
	if len(left) != 2 || !left["idle13"] || !left["new"] {
		t.Fatalf("sessions left %v", left)
	}
	// with many idle days the absolute limit still prunes
	d.Exec("UPDATE sessions SET created = ? WHERE hash = 'new'", at(now.Add(-SessionMax-time.Hour)))
	if p, err := d.Prune(now, Retention{SessionDays: 3650}); err != nil || p.Sessions != 1 {
		t.Fatalf("pruned %+v %v", p, err)
	}
}
