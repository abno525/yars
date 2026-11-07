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
// with hash ContentHash. Done of Total rules have run so far.
type CheckRun struct {
	ID                    int64
	Eng, Fid, ContentHash string
	Started, Finished     string // RFC 3339; Finished "" while running
	State, By, Error      string
	Total, Done           int
}

// CheckResult is one violation a run found. Thread is the chat thread that
// stands for it ("" = none: a notice, or a dismissed violation).
type CheckResult struct {
	RunID                               int64
	Rule, Level, Message, Target, Quote string
	QuoteHash, Thread                   string
}

// Dismissal says a violation (rule + hash of its quote) of a finding no
// longer counts: By dismissed it At, for Reason.
type Dismissal struct {
	Eng, Fid, Rule, QuoteHash string
	Level, By, At, Reason     string
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

// AddSteps records the steps of a run (queued ones, or ones carried over
// from an earlier run).
func (d *DB) AddSteps(steps []CheckStep) error {
	for _, x := range steps {
		if _, err := d.Exec(`INSERT INTO check_steps(run_id, pos, rule, kind, state, started, finished, hits, message, fail)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, x.RunID, x.Pos, x.Rule, x.Kind, x.State, x.Started, x.Finished, x.Hits, x.Message, x.Fail); err != nil {
			return err
		}
	}
	return nil
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

// DismissKey identifies a violation of a finding across runs and edits.
func DismissKey(rule, quoteHash string) string { return rule + "\x00" + quoteHash }

const runCols = "id, eng, fid, content_hash, started, finished, state, by_user, total, done_count, error"

func scanRun(sc interface{ Scan(...any) error }) (CheckRun, error) {
	var r CheckRun
	err := sc.Scan(&r.ID, &r.Eng, &r.Fid, &r.ContentHash, &r.Started, &r.Finished, &r.State, &r.By, &r.Total, &r.Done, &r.Error)
	return r, err
}

// StartRun records a new running check of eng/fid by user. It moves no
// change counter: progress is announced through the event hub. An archived
// engagement gets none (ErrArchived), checked in the same statement.
func (d *DB) StartRun(eng, fid, contentHash, user string) (int64, error) {
	res, err := d.Exec(`INSERT INTO check_runs(eng, fid, content_hash, started, state, by_user)
		SELECT ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM engagement_meta WHERE eng = ? AND archived_at != '')`,
		eng, fid, contentHash, d.stamp(), RunRunning, user, eng)
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
	r, err := scanRun(d.QueryRow("SELECT "+runCols+" FROM check_runs WHERE eng = ? AND fid = ? AND content_hash = ? AND state != ? AND finished != '' AND done_count = total ORDER BY id DESC LIMIT 1",
		eng, fid, contentHash, RunRunning))
	if errors.Is(err, sql.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}

// RunCount is a finding's newest check run in short: its state, the content
// it ran on, and its errors and warnings that are not dismissed (notices
// about the rules or AI left out).
type RunCount struct {
	ID                 int64
	State, ContentHash string
	Errors, Warnings   int
}

// LatestRuns reads the newest run of each finding (eng, fid) in one query
// per 200 findings, by "eng/fid"; a finding never checked is left out.
func (d *DB) LatestRuns(keys [][2]string) (map[string]RunCount, error) {
	out := map[string]RunCount{}
	const count = `(SELECT count(*) FROM check_results r WHERE r.run_id = c.id AND r.level = ? AND r.target NOT IN ('rules', 'ai')
		AND NOT EXISTS (SELECT 1 FROM dismissals x WHERE x.eng = c.eng AND x.fid = c.fid AND x.rule = r.rule AND x.quote_hash = r.quote_hash))`
	for len(keys) > 0 {
		part := keys[:min(len(keys), 200)]
		keys = keys[len(part):]
		args := []any{"error", "warning"}
		vals := make([]string, len(part))
		for i, k := range part {
			vals[i] = "(?, ?)"
			args = append(args, k[0], k[1])
		}
		rows, err := d.Query(`SELECT c.eng, c.fid, c.id, c.state, c.content_hash, `+count+`, `+count+`
			FROM check_runs c WHERE c.id IN (SELECT MAX(id) FROM check_runs WHERE (eng, fid) IN (VALUES `+strings.Join(vals, ", ")+`) GROUP BY eng, fid)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var eng, fid string
			var r RunCount
			if err := rows.Scan(&eng, &fid, &r.ID, &r.State, &r.ContentHash, &r.Errors, &r.Warnings); err != nil {
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
	if _, err := tx.Exec("UPDATE check_runs SET state = ?, error = ?, finished = ?, done_count = total WHERE id = ?",
		state, reason, stampNow(), id); err != nil {
		return err
	}
	for _, r := range results {
		if _, err := tx.Exec(`INSERT INTO check_results(run_id, rule, level, message, target, quote, quote_hash, thread)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, id, r.Rule, r.Level, r.Message, r.Target, r.Quote, r.QuoteHash, r.Thread); err != nil {
			return err
		}
	}
	return nil
}

// RunResults returns a run's violations in the order found.
func (d *DB) RunResults(id int64) ([]CheckResult, error) {
	rows, err := d.Query("SELECT run_id, rule, level, message, target, quote, quote_hash, thread FROM check_results WHERE run_id = ? ORDER BY rowid", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CheckResult
	for rows.Next() {
		var r CheckResult
		if err := rows.Scan(&r.RunID, &r.Rule, &r.Level, &r.Message, &r.Target, &r.Quote, &r.QuoteHash, &r.Thread); err != nil {
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
	rows, err := q.Query("SELECT eng, fid, rule, quote_hash, level, by_user, at, reason FROM dismissals WHERE eng = ? AND fid = ?", eng, fid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Dismissal{}
	for rows.Next() {
		var x Dismissal
		if err := rows.Scan(&x.Eng, &x.Fid, &x.Rule, &x.QuoteHash, &x.Level, &x.By, &x.At, &x.Reason); err != nil {
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
	_, err := tx.Exec(`INSERT INTO dismissals(eng, fid, rule, quote_hash, level, by_user, at, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(eng, fid, rule, quote_hash) DO UPDATE SET level = excluded.level, by_user = excluded.by_user, at = excluded.at, reason = excluded.reason`,
		x.Eng, x.Fid, x.Rule, x.QuoteHash, x.Level, x.By, x.At, x.Reason)
	return err
}

// Undismiss drops a dismissal; the violation counts again.
func (tx *Tx) Undismiss(eng, fid, rule, quoteHash string) error {
	tx.touch(eng)
	_, err := tx.Exec("DELETE FROM dismissals WHERE eng = ? AND fid = ? AND rule = ? AND quote_hash = ?", eng, fid, rule, quoteHash)
	return err
}
