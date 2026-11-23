package db

import (
	"testing"
	"time"
)

// D24: AI usage sums by everyone first, then per user by calls; only calls
// since the given time count.
func TestAITotals(t *testing.T) {
	d, _ := open(t)
	now := time.Now()
	for _, u := range []AIUsage{
		{TS: at(now.Add(-time.Hour)), User: "alice", Purpose: "rule", Provider: "openai", Model: "m1", Rule: "acr", In: 100, Out: 10, MS: 800, OK: true},
		{TS: at(now.Add(-2 * time.Hour)), User: "bob", Purpose: "rule", Provider: "openai", Model: "m1", In: 50, Out: 5, OK: true},
		{TS: at(now.Add(-3 * time.Hour)), User: "alice", Purpose: "test", Provider: "openai", Model: "m1", In: 20, Out: 2},
		{TS: at(now.AddDate(0, 0, -40)), User: "carol", Purpose: "rule", Provider: "openai", Model: "m1", In: 9999, Out: 999, OK: true},
	} {
		if err := d.AddAIUsage(u); err != nil {
			t.Fatal(err)
		}
	}
	got, err := d.AITotals(now.AddDate(0, 0, -30))
	if err != nil {
		t.Fatal(err)
	}
	want := []AITotal{{User: "", Calls: 3, In: 170, Out: 17}, {User: "alice", Calls: 2, In: 120, Out: 12}, {User: "bob", Calls: 1, In: 50, Out: 5}}
	if len(got) != len(want) {
		t.Fatalf("totals %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("totals %+v, want %+v", got, want)
		}
	}
	// nothing since: one row, the total, all zero
	if got, _ := d.AITotals(now.Add(time.Hour)); len(got) != 1 || got[0] != (AITotal{}) {
		t.Fatalf("empty totals %+v", got)
	}
}

// D24: the retention's audit days prune AI usage too.
func TestPruneAIUsage(t *testing.T) {
	d, _ := open(t)
	now := time.Now()
	d.AddAIUsage(AIUsage{TS: at(now.AddDate(0, 0, -40)), Purpose: "rule", Provider: "openai", Model: "m1"})
	d.AddAIUsage(AIUsage{TS: at(now), Purpose: "rule", Provider: "openai", Model: "m1"})
	p, err := d.Prune(now, Retention{AuditDays: 30})
	if err != nil || p.AIUsage != 1 {
		t.Fatalf("pruned %+v %v", p, err)
	}
	if count(t, d, "ai_usage") != 1 {
		t.Fatal("the newer call was pruned")
	}
}
