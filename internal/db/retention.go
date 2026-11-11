package db

import (
	"fmt"
	"strconv"
	"time"
)

// Retention is how long things are kept, in days; 0 keeps them for good
// (D24, Admin › System).
type Retention struct{ AuditDays, CheckRunDays, SessionDays int }

// Setting keys and defaults.
const (
	RetainAuditKey    = "retention.audit_days"     // default 0
	RetainCheckRunKey = "retention.check_run_days" // default 90
	RetainSessionKey  = "retention.session_days"   // default 14
)

// retainMax is the longest retention one may set (ten years).
const retainMax = 3650

// Retention returns the settings with the defaults applied (one query: it
// is read on every request through SessionUser).
func (d *DB) Retention() (Retention, error) {
	r := Retention{AuditDays: 0, CheckRunDays: 90, SessionDays: 14}
	set, err := d.Settings("retention.")
	if err != nil {
		return r, err
	}
	for key, n := range map[string]*int{RetainAuditKey: &r.AuditDays, RetainCheckRunKey: &r.CheckRunDays, RetainSessionKey: &r.SessionDays} {
		if v, ok := set[key]; ok && v != "" {
			if days, err := strconv.Atoi(v); err == nil && days >= 0 && days <= retainMax {
				*n = days
			}
		}
	}
	return r, nil
}

// SetRetention stores the settings; each value is 0–3650, or nothing is
// stored.
func (d *DB) SetRetention(r Retention) error {
	vals := [][2]any{{RetainAuditKey, r.AuditDays}, {RetainCheckRunKey, r.CheckRunDays}, {RetainSessionKey, r.SessionDays}}
	for _, kv := range vals {
		if n := kv[1].(int); n < 0 || n > retainMax {
			return fmt.Errorf("%s: %d is not between 0 and %d days", kv[0], n, retainMax)
		}
	}
	for _, kv := range vals { // all checked first: a refused value stores nothing
		if err := d.SetSetting(kv[0].(string), strconv.Itoa(kv[1].(int))); err != nil {
			return err
		}
	}
	return nil
}

// Pruned counts what a Prune deleted (AIUsage: calls to the AI provider,
// which the audit days keep as long as the audit log).
type Pruned struct{ Audit, CheckRuns, Sessions, AIUsage int }

// Prune deletes what is older than r allows at now: audit entries, finished
// check runs other than each finding's latest (their results and steps go
// with them), and sessions not used for SessionDays. A value of 0 keeps
// that kind for good.
func (d *DB) Prune(now time.Time, r Retention) (Pruned, error) {
	var p Pruned
	cutoff := func(days int) string { return now.AddDate(0, 0, -days).UTC().Format(time.RFC3339) }
	del := func(n *int, q string, args ...any) error {
		res, err := d.Exec(q, args...)
		if err != nil {
			return err
		}
		k, err := res.RowsAffected()
		*n = int(k)
		return err
	}
	if r.AuditDays > 0 {
		if err := del(&p.Audit, "DELETE FROM audit WHERE ts < ?", cutoff(r.AuditDays)); err != nil {
			return p, err
		}
		if err := del(&p.AIUsage, "DELETE FROM ai_usage WHERE ts < ?", cutoff(r.AuditDays)); err != nil {
			return p, err
		}
	}
	if r.CheckRunDays > 0 {
		// the latest run of a finding stays whatever its age: the Require
		// Check gate reads it
		if err := del(&p.CheckRuns, `DELETE FROM check_runs WHERE finished != '' AND finished < ?
			AND id NOT IN (SELECT max(id) FROM check_runs GROUP BY eng, fid)`, cutoff(r.CheckRunDays)); err != nil {
			return p, err
		}
	}
	if r.SessionDays > 0 {
		if err := del(&p.Sessions, "DELETE FROM sessions WHERE last_seen < ?", cutoff(r.SessionDays)); err != nil {
			return p, err
		}
	}
	return p, nil
}

// sessionIdle is how long a session lives without being used: the
// retention's session days, or SessionIdle when that is 0.
func (d *DB) sessionIdle() time.Duration {
	r, err := d.Retention()
	if err != nil || r.SessionDays == 0 {
		return SessionIdle
	}
	return time.Duration(r.SessionDays) * 24 * time.Hour
}
