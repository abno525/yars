package db

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

func stampNow() string { return time.Now().UTC().Format(time.RFC3339) }

// Check run states.
const (
	RunRunning = "running"
	RunDone    = "done"
	RunFailed  = "failed"
)

// CheckRun is one run of every style rule on a finding, for the content
// with hash ContentHash: the full SHA-256 of finding.md, or its first 16
// digits in a run stored before the full digest was kept (SameContent). Done
// of Total rules have run so far.
type CheckRun struct {
	ID                    int64
	Eng, Fid, ContentHash string
	Started, Finished     string // RFC 3339; Finished "" while running
	State, By, Error      string
	Total, Done           int
	Rules                 string // the rules' version it checked with ("" = before v19, or unknown)
}

// SameContent reports whether a hash stored with a check run, an approval or
// a sign-off is of the content whose full digest is full. A stored value of
// 16 digits is from before the full digest was kept: it counts for the
// content whose digest starts with it, with the 64 bits it always had.
func SameContent(stored, full string) bool {
	return stored == full || len(stored) == 16 && len(full) > 16 && strings.HasPrefix(full, stored)
}

// shortOf is the 16 digits a hash was stored as before the full digest was
// kept.
func shortOf(h string) string { return h[:min(len(h), 16)] }

// CheckResult is one violation a run found. Thread is the chat thread that
// stands for it ("" = none: a notice, or a dismissed violation).
type CheckResult struct {
	RunID                               int64
	Rule, Level, Message, Target, Quote string
	QuoteHash, Thread                   string
	// Matches is how many matches the row stands for: the same wording a
	// pattern found again in the same place is the same row. 0 reads as 1.
	Matches int
}

// Dismissal says a violation (rule + hash of its quote) of a finding no
// longer counts: By dismissed it At, for Reason.
type Dismissal struct {
	Eng, Fid, Rule, QuoteHash string
	Level, By, At, Reason     string
	// Covers is how many matches the row stood for when it was dismissed: a
	// row with more is not covered (Holds). 0 is a dismissal made before
	// counts were kept: it covers any number until a check run writes the
	// count it finds.
	Covers int
}

// Holds reports whether the dismissal covers its row when the row stands
// for n matches.
func (x Dismissal) Holds(n int) bool { return x.Covers == 0 || n <= x.Covers }

// Covering is Lookup for a row that stands for n matches: the dismissal of
// the violation (rule, target, quote) when it covers that many.
func Covering(ds map[string]Dismissal, rule, target, quote string, n int) (Dismissal, bool) {
	d, ok := Lookup(ds, rule, target, quote)
	if !ok || !d.Holds(n) {
		return Dismissal{}, false
	}
	return d, true
}

// Check step states: a rule of a run waits, runs, then passes, finds
// violations (hits) or could not run (failed).
const (
	StepQueued  = "queued"
	StepRunning = "running"
	StepPass    = "pass"
	StepHits    = "hits"
	StepFailed  = "failed"
)

// CheckStep is one rule of a check run. Kind is the rule's kind (pattern,
// builtin, script, ai); Message says why a failed rule could not run and
// Fail is its stored reason ("invalid output", …).
type CheckStep struct {
	RunID             int64
	Pos               int
	Rule, Kind, State string
	Started, Finished string // RFC 3339 with fractions; "" = not yet
	Hits              int
	Message, Fail     string
}

// StepStamp is a step's time: RFC 3339 with milliseconds, so a 0.8 s rule
// shows as such.
func StepStamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z07:00") }

const insertStep = `INSERT INTO check_steps(run_id, pos, rule, kind, state, started, finished, hits, message, fail)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// AddSteps records the steps of a run (queued ones, or ones carried over
// from an earlier run).
func (d *DB) AddSteps(steps []CheckStep) error {
	for _, x := range steps {
		if _, err := d.Exec(insertStep, x.RunID, x.Pos, x.Rule, x.Kind, x.State, x.Started, x.Finished, x.Hits, x.Message, x.Fail); err != nil {
			return err
		}
	}
	return nil
}

// SetSteps replaces the steps of run with steps, in one transaction (the
// rules changed before it ran).
func (d *DB) SetSteps(run int64, steps []CheckStep) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("DELETE FROM check_steps WHERE run_id = ?", run); err != nil {
		return err
	}
	for _, x := range steps {
		if _, err := tx.Exec(insertStep, run, x.Pos, x.Rule, x.Kind, x.State, x.Started, x.Finished, x.Hits, x.Message, x.Fail); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// StepStarted marks a rule of a run as running now.
func (d *DB) StepStarted(run int64, rule string, at time.Time) error {
	_, err := d.Exec("UPDATE check_steps SET state = ?, started = ?, finished = '', hits = 0, message = '', fail = '' WHERE run_id = ? AND rule = ?",
		StepRunning, StepStamp(at), run, rule)
	return err
}

// StepDone records how a rule of a run ended.
func (d *DB) StepDone(x CheckStep) error {
	_, err := d.Exec("UPDATE check_steps SET state = ?, finished = ?, hits = ?, message = ?, fail = ? WHERE run_id = ? AND rule = ?",
		x.State, x.Finished, x.Hits, x.Message, x.Fail, x.RunID, x.Rule)
	return err
}

// RunSteps returns the steps of a run in rule order.
func (d *DB) RunSteps(run int64) ([]CheckStep, error) {
	rows, err := d.Query("SELECT run_id, pos, rule, kind, state, started, finished, hits, message, fail FROM check_steps WHERE run_id = ? ORDER BY pos", run)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckStep
	for rows.Next() {
		var x CheckStep
		if err := rows.Scan(&x.RunID, &x.Pos, &x.Rule, &x.Kind, &x.State, &x.Started, &x.Finished, &x.Hits, &x.Message, &x.Fail); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// FailedAIRuns reports which of the runs have a step of kind ai that failed
// (the rule could not run).
func (d *DB) FailedAIRuns(ids []int64) (map[int64]bool, error) {
	out := map[int64]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	args := []any{"ai", StepFailed}
	for _, id := range ids {
		args = append(args, id)
	}
	rows, err := d.Query("SELECT DISTINCT run_id FROM check_steps WHERE kind = ? AND state = ? AND run_id IN (?"+strings.Repeat(", ?", len(ids)-1)+")", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// DismissKey identifies a violation of a finding across runs and edits.
func DismissKey(rule, quoteHash string) string { return rule + "\x00" + quoteHash }

const runCols = "id, eng, fid, content_hash, started, finished, state, by_user, total, done_count, error, rules_version"

func scanRun(sc interface{ Scan(...any) error }) (CheckRun, error) {
	var r CheckRun
	err := sc.Scan(&r.ID, &r.Eng, &r.Fid, &r.ContentHash, &r.Started, &r.Finished, &r.State, &r.By, &r.Total, &r.Done, &r.Error, &r.Rules)
	return r, err
}

// StartRun records a new running check of eng/fid by user with the rules at
// version rules. It moves no change counter: progress is announced through
// the event hub. An archived engagement gets none (ErrArchived), checked in
// the same statement.
func (d *DB) StartRun(eng, fid, contentHash, user, rules string) (int64, error) {
	res, err := d.Exec(`INSERT INTO check_runs(eng, fid, content_hash, started, state, by_user, rules_version)
		SELECT ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM engagement_meta WHERE eng = ? AND archived_at != '')`,
		eng, fid, contentHash, d.stamp(), RunRunning, user, rules, eng)
	if err != nil {
		return 0, err
	}
	if n, err := res.RowsAffected(); err != nil {
		return 0, err
	} else if n == 0 {
		return 0, ErrArchived
	}
	return res.LastInsertId()
}

// SetRunRules records the version of the rules a check run ran with.
func (d *DB) SetRunRules(id int64, rules string) error {
	_, err := d.Exec("UPDATE check_runs SET rules_version = ? WHERE id = ?", rules, id)
	return err
}

// RunProgress records that done of total rules of a running check ran.
func (d *DB) RunProgress(id int64, done, total int) error {
	_, err := d.Exec("UPDATE check_runs SET done_count = ?, total = ? WHERE id = ? AND state = ?", done, total, id, RunRunning)
	return err
}

// Run returns one check run.
func (d *DB) Run(id int64) (CheckRun, error) {
	r, err := scanRun(d.QueryRow("SELECT "+runCols+" FROM check_runs WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// LatestRun returns the newest check run of a finding (false when none).
func (d *DB) LatestRun(eng, fid string) (CheckRun, bool, error) {
	r, err := scanRun(d.QueryRow("SELECT "+runCols+" FROM check_runs WHERE eng = ? AND fid = ? ORDER BY id DESC LIMIT 1", eng, fid))
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}

// LatestFinishedRun returns the newest check run of a finding that ended
// with its results stored (FinishRun: done, or failed when a rule could not
// run) on the given content (false when none): a run in progress, or one
// cut off without results (FailRun: interrupted, crashed), never hides the
// one before it.
func (d *DB) LatestFinishedRun(eng, fid, contentHash string) (CheckRun, bool, error) {
	runs, err := d.FinishedRuns(eng, fid, contentHash, 1)
	if err != nil || len(runs) == 0 {
		return CheckRun{}, false, err
	}
	return runs[0], true, nil
}

// FinishedRuns returns up to limit check runs of a finding that ended with
// their results stored on the given content (its full digest; a run stored
// under the digest's first 16 digits counts, SameContent), newest first (see
// LatestFinishedRun).
func (d *DB) FinishedRuns(eng, fid, contentHash string, limit int) ([]CheckRun, error) {
	rows, err := d.Query("SELECT "+runCols+" FROM check_runs WHERE eng = ? AND fid = ? AND content_hash IN (?, ?) AND state != ? AND stored = 1 ORDER BY id DESC LIMIT ?",
		eng, fid, contentHash, shortOf(contentHash), RunRunning, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RunCount is a finding's newest check run in short: its state, the content
// it ran on, and its errors and warnings that are not dismissed (notices
// about the rules or AI left out).
type RunCount struct {
	ID                 int64
	State, ContentHash string
	Errors, Warnings   int
	Rules              string // the rules' version it checked with
}

// LatestRuns reads the newest run of each finding (eng, fid) in one query
// per 200 findings, by "eng/fid"; a finding never checked is left out.
func (d *DB) LatestRuns(keys [][2]string) (map[string]RunCount, error) {
	out := map[string]RunCount{}
	// one per result row (rule and place): runs before that stored a quote
	// found twice in one place twice
	const count = `(SELECT count(DISTINCT r.rule || char(0) || r.quote_hash) FROM check_results r WHERE r.run_id = c.id AND r.level = ? AND r.target NOT IN ('rules', 'ai')
		AND NOT EXISTS (SELECT 1 FROM dismissals x WHERE x.eng = c.eng AND x.fid = c.fid AND x.rule = r.rule AND x.quote_hash = r.quote_hash
			AND (x.covers = 0 OR x.covers >= r.matches)))`
	for len(keys) > 0 {
		part := keys[:min(len(keys), 200)]
		keys = keys[len(part):]
		args := []any{"error", "warning"}
		vals := make([]string, len(part))
		for i, k := range part {
			vals[i] = "(?, ?)"
			args = append(args, k[0], k[1])
		}
		rows, err := d.Query(`SELECT c.eng, c.fid, c.id, c.state, c.content_hash, `+count+`, `+count+`, c.rules_version
			FROM check_runs c WHERE c.id IN (SELECT MAX(id) FROM check_runs WHERE (eng, fid) IN (VALUES `+strings.Join(vals, ", ")+`) GROUP BY eng, fid)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var eng, fid string
			var r RunCount
			if err := rows.Scan(&eng, &fid, &r.ID, &r.State, &r.ContentHash, &r.Errors, &r.Warnings, &r.Rules); err != nil {
				rows.Close()
				return nil, err
			}
			out[eng+"/"+fid] = r
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// FailRun ends a running check as failed (e.g. a run cut off by a restart).
func (d *DB) FailRun(id int64, reason string) error {
	res, err := d.Exec("UPDATE check_runs SET state = ?, error = ?, finished = ? WHERE id = ? AND state = ?", RunFailed, reason, d.stamp(), id, RunRunning)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil
	}
	// the rules that had not ended never will
	_, err = d.Exec("UPDATE check_steps SET state = ?, message = ?, fail = ? WHERE run_id = ? AND state IN (?, ?)",
		StepFailed, reason, reason, id, StepQueued, StepRunning)
	return err
}

// FinishRun ends a check run in state with its results.
func (tx *Tx) FinishRun(id int64, state, reason string, results []CheckResult) error {
	var eng string
	if err := tx.QueryRow("SELECT eng FROM check_runs WHERE id = ?", id).Scan(&eng); err != nil {
		return err
	}
	tx.touch(eng)
	if _, err := tx.Exec("UPDATE check_runs SET state = ?, error = ?, finished = ?, done_count = total, stored = 1 WHERE id = ?",
		state, reason, stampNow(), id); err != nil {
		return err
	}
	for _, r := range results {
		if _, err := tx.Exec(`INSERT INTO check_results(run_id, rule, level, message, target, quote, quote_hash, thread, matches)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, r.Rule, r.Level, r.Message, r.Target, r.Quote, r.QuoteHash, r.Thread, max(r.Matches, 1)); err != nil {
			return err
		}
	}
	return nil
}

// RunResults returns a run's violations in the order found.
func (d *DB) RunResults(id int64) ([]CheckResult, error) {
	rows, err := d.Query("SELECT run_id, rule, level, message, target, quote, quote_hash, thread, matches FROM check_results WHERE run_id = ? ORDER BY rowid", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckResult
	for rows.Next() {
		var r CheckResult
		if err := rows.Scan(&r.RunID, &r.Rule, &r.Level, &r.Message, &r.Target, &r.Quote, &r.QuoteHash, &r.Thread, &r.Matches); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CheckThreadRef is a violation (rule + quote hash) and the chat thread a run
// gave it.
type CheckThreadRef struct {
	Rule, QuoteHash, Thread string
}

// CheckThreadRefs lists every violation of a finding with the thread a run
// gave it, oldest run first.
func (tx *Tx) CheckThreadRefs(eng, fid string) ([]CheckThreadRef, error) {
	rows, err := tx.Query(`SELECT r.rule, r.quote_hash, r.thread FROM check_results r JOIN check_runs c ON c.id = r.run_id
		WHERE c.eng = ? AND c.fid = ? AND r.thread != '' ORDER BY r.run_id, r.rowid`, eng, fid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckThreadRef
	for rows.Next() {
		var x CheckThreadRef
		if err := rows.Scan(&x.Rule, &x.QuoteHash, &x.Thread); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// Dismissals returns a finding's dismissed violations by DismissKey.
func (d *DB) Dismissals(eng, fid string) (map[string]Dismissal, error) {
	return dismissals(d, eng, fid)
}

// Dismissals reads them inside the transaction.
func (tx *Tx) Dismissals(eng, fid string) (map[string]Dismissal, error) {
	return dismissals(tx, eng, fid)
}

func dismissals(q querier, eng, fid string) (map[string]Dismissal, error) {
	rows, err := q.Query("SELECT eng, fid, rule, quote_hash, level, by_user, at, reason, covers FROM dismissals WHERE eng = ? AND fid = ?", eng, fid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Dismissal{}
	for rows.Next() {
		var x Dismissal
		if err := rows.Scan(&x.Eng, &x.Fid, &x.Rule, &x.QuoteHash, &x.Level, &x.By, &x.At, &x.Reason, &x.Covers); err != nil {
			return nil, err
		}
		out[DismissKey(x.Rule, x.QuoteHash)] = x
	}
	return out, rows.Err()
}

// Dismiss records a dismissal (replacing an earlier one of the same
// violation); At is set when empty.
func (tx *Tx) Dismiss(x Dismissal) error {
	tx.touch(x.Eng)
	if x.At == "" {
		x.At = stampNow()
	}
	_, err := tx.Exec(`INSERT INTO dismissals(eng, fid, rule, quote_hash, level, by_user, at, reason, covers) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(eng, fid, rule, quote_hash) DO UPDATE SET level = excluded.level, by_user = excluded.by_user, at = excluded.at, reason = excluded.reason,
			covers = excluded.covers`,
		x.Eng, x.Fid, x.Rule, x.QuoteHash, x.Level, x.By, x.At, x.Reason, x.Covers)
	return err
}

// RenameRule gives what is stored under rule from to rule to, in every
// engagement (the rule was renamed), in one transaction: its dismissals
// (moved is how many), and the results and steps of the stored check runs,
// so a result dismissed before is the dismissed result still, and its chat
// thread stays the result's (CheckThreadRefs). A place that rule to has a
// dismissal for already keeps that one; from's is dropped, so none is left
// under the old ID. A run that has a step of rule to already keeps that step
// and from's beside it.
func (d *DB) RenameRule(from, to string) (moved int, err error) {
	err = d.Tx(func(tx *Tx) error {
		rows, err := tx.Query(`SELECT eng FROM dismissals WHERE rule = ?
			UNION SELECT c.eng FROM check_runs c JOIN check_results r ON r.run_id = c.id WHERE r.rule = ?
			UNION SELECT c.eng FROM check_runs c JOIN check_steps x ON x.run_id = c.id WHERE x.rule = ?`, from, from, from)
		if err != nil {
			return err
		}
		var engs []string
		for rows.Next() {
			var e string
			if err := rows.Scan(&e); err != nil {
				rows.Close()
				return err
			}
			engs = append(engs, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, e := range engs {
			tx.touch(e)
		}
		res, err := tx.Exec("UPDATE OR IGNORE dismissals SET rule = ? WHERE rule = ?", to, from)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		moved = int(n)
		if _, err = tx.Exec("DELETE FROM dismissals WHERE rule = ?", from); err != nil {
			return err
		}
		if _, err = tx.Exec("UPDATE check_results SET rule = ? WHERE rule = ?", to, from); err != nil {
			return err
		}
		_, err = tx.Exec("UPDATE OR IGNORE check_steps SET rule = ? WHERE rule = ?", to, from)
		return err
	})
	return moved, err
}

// RetargetResults moves what is stored for finding fid under the place from
// to the place to (a section or details row was renamed): the results of
// its check runs, with the key that names the place, and the dismissals of
// those rows. A dismissal whose row no run stored is not found this way and
// stays under the old place. A place that has a dismissal under the new
// name already keeps that one. Nothing changes when nothing is stored under
// from, so it can run again.
func (tx *Tx) RetargetResults(eng, fid, from, to string) error {
	if from == to {
		return nil
	}
	type row struct {
		id              int64
		rule, quote, qh string
	}
	rows, err := tx.Query(`SELECT r.rowid, r.rule, r.quote, r.quote_hash FROM check_results r JOIN check_runs c ON c.id = r.run_id
		WHERE c.eng = ? AND c.fid = ? AND r.target = ?`, eng, fid, from)
	if err != nil {
		return err
	}
	var all []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.id, &x.rule, &x.quote, &x.qh); err != nil {
			rows.Close()
			return err
		}
		all = append(all, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(all) == 0 {
		return nil
	}
	tx.touch(eng)
	for _, x := range all {
		now := x.qh
		if x.qh == ViolationHash(from, x.quote) { // keyed by its place, as every row since v14
			now = ViolationHash(to, x.quote)
			if _, err := tx.Exec("UPDATE OR IGNORE dismissals SET quote_hash = ? WHERE eng = ? AND fid = ? AND rule = ? AND quote_hash = ?", now, eng, fid, x.rule, x.qh); err != nil {
				return err
			}
			if _, err := tx.Exec("DELETE FROM dismissals WHERE eng = ? AND fid = ? AND rule = ? AND quote_hash = ?", eng, fid, x.rule, x.qh); err != nil {
				return err
			}
		}
		if _, err := tx.Exec("UPDATE check_results SET target = ?, quote_hash = ? WHERE rowid = ?", to, now, x.id); err != nil {
			return err
		}
	}
	return nil
}

// Undismiss drops a dismissal; the violation counts again.
func (tx *Tx) Undismiss(eng, fid, rule, quoteHash string) error {
	tx.touch(eng)
	_, err := tx.Exec("DELETE FROM dismissals WHERE eng = ? AND fid = ? AND rule = ? AND quote_hash = ?", eng, fid, rule, quoteHash)
	return err
}
