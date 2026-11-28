package db

import (
	"testing"
	"time"
)

// The AI spend limit counts the last AILimitDays days of usage, so the
// prune keeps the usage rows that long whatever the audit days are: with a
// shorter audit retention the limit would forget real spend and never be
// reached. The audit log itself is pruned as before.
func TestPruneKeepsUsageTheLimitCounts(t *testing.T) {
	d, _ := open(t)
	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	at := func(days int) string { return now.AddDate(0, 0, -days).Format(time.RFC3339) }
	for _, days := range []int{1, 20, 40} {
		if err := d.AddAIUsage(AIUsage{TS: at(days), User: "alice", Purpose: "rule", In: 1000, Out: 100, OK: true}); err != nil {
			t.Fatal(err)
		}
	}
	p, err := d.Prune(now, Retention{AuditDays: 7, CheckRunDays: 90, SessionDays: 14})
	if err != nil {
		t.Fatal(err)
	}
	if p.AIUsage != 1 {
		t.Fatalf("pruned %d usage rows, want the one older than %d days", p.AIUsage, AILimitDays)
	}
	in, out, err := d.AITokens(now.AddDate(0, 0, -AILimitDays))
	if err != nil || in != 2000 || out != 200 {
		t.Fatalf("tokens the limit counts after the prune: %d in, %d out, %v", in, out, err)
	}
	// audit days longer than the limit's period keep the rows as long as the
	// audit log, as before
	if p, err := d.Prune(now, Retention{AuditDays: 60}); err != nil || p.AIUsage != 0 {
		t.Fatalf("with 60 audit days: %+v %v", p, err)
	}
}
