package db

import (
	"database/sql"
	"strconv"
	"time"

	"yars/internal/chat"
)

// Reviewer is an assigned reviewer; ClearedHash is the hash of finding.md
// when they cleared it ("" = not cleared). A clearance counts only while the
// file still has that hash, so any content change voids it.
type Reviewer struct{ Name, ClearedHash string }

// State is a finding's workflow state. A finding with no stored state is a
// draft with no reviewers.
type State struct {
	Status                     string
	Reviewers                  []Reviewer
	ReturnedBy, ReturnedReason string
	RetestSource, RetestResult string
	// ApprovedHash is the finding.md hash at approval; a complete finding
	// whose content no longer matches is back in verification.
	ApprovedHash string
	// WithdrawnBy and WithdrawnReason say who took the finding out of the
	// report and why (status withdrawn).
	WithdrawnBy, WithdrawnReason string
}

func scanState(sc interface{ Scan(...any) error }) (string, State, error) {
	var fid string
	var s State
	err := sc.Scan(&fid, &s.Status, &s.ReturnedBy, &s.ReturnedReason, &s.RetestSource, &s.RetestResult, &s.ApprovedHash,
		&s.WithdrawnBy, &s.WithdrawnReason)
	return fid, s, err
}

const stateCols = "fid, status, returned_by, returned_reason, retest_source, retest_result, approved_hash, withdrawn_by, withdrawn_reason"

// querier is what both *DB and *Tx can run reads on.
type querier interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

// State returns one finding's workflow state.
func (d *DB) State(eng, fid string) (State, error) { return stateOf(d, eng, fid) }

// State reads one finding's state inside the transaction, so a
// read-modify-write can't lose a concurrent writer's change.
func (tx *Tx) State(eng, fid string) (State, error) { return stateOf(tx, eng, fid) }

func stateOf(q querier, eng, fid string) (State, error) {
	all, err := states(q, eng, fid)
	if err != nil {
		return State{}, err
	}
	if s, ok := all[fid]; ok {
		return s, nil
	}
	return State{Status: "draft"}, nil
}

// States returns the stored state of every finding in an engagement, by ID.
func (d *DB) States(eng string) (map[string]State, error) { return states(d, eng, "") }

// Known reports whether a finding ID has (or had) workflow state or chat.
// A new finding must not reuse such an ID, or it would inherit them.
func (d *DB) Known(eng, fid string) (bool, error) {
	var n int
	err := d.QueryRow(`SELECT (SELECT count(*) FROM finding_state WHERE eng = ?1 AND fid = ?2)
		+ (SELECT count(*) FROM reviewers WHERE eng = ?1 AND fid = ?2)
		+ (SELECT count(*) FROM chat WHERE eng = ?1 AND fid = ?2)`, eng, fid).Scan(&n)
	return n > 0, err
}

// Purge drops all workflow state and chat of an engagement (used when an
// engagement is created under the name of one that no longer exists).
func (tx *Tx) Purge(eng string) error {
	tx.touch(eng)
	for _, t := range []string{"finding_state", "reviewers", "chat", "chat_hidden"} {
		if _, err := tx.Exec("DELETE FROM "+t+" WHERE eng = ?", eng); err != nil {
			return err
		}
	}
	return nil
}

func states(d querier, eng, fid string) (map[string]State, error) {
	q, args := "SELECT "+stateCols+" FROM finding_state WHERE eng = ?", []any{eng}
	rq, rargs := "SELECT fid, username, COALESCE(cleared_hash, '') FROM reviewers WHERE eng = ?", []any{eng}
	if fid != "" {
		q, args = q+" AND fid = ?", append(args, fid)
		rq, rargs = rq+" AND fid = ?", append(rargs, fid)
	}
	out := map[string]State{}
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		f, s, err := scanState(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out[f] = s
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rrows, err := d.Query(rq+" ORDER BY rowid", rargs...)
	if err != nil {
		return nil, err
	}
	defer rrows.Close()
	for rrows.Next() {
		var f string
		var r Reviewer
		if err := rrows.Scan(&f, &r.Name, &r.ClearedHash); err != nil {
			return nil, err
		}
		s, ok := out[f]
		if !ok {
			s.Status = "draft"
		}
		s.Reviewers = append(s.Reviewers, r)
		out[f] = s
	}
	return out, rrows.Err()
}

// PutState replaces a finding's whole workflow state.
func (tx *Tx) PutState(eng, fid string, s State) error {
	tx.touch(eng)
	if s.Status == "" {
		s.Status = "draft"
	}
	_, err := tx.Exec(`INSERT INTO finding_state(eng, fid, status, returned_by, returned_reason, retest_source, retest_result, approved_hash,
		withdrawn_by, withdrawn_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(eng, fid) DO UPDATE SET status = excluded.status, returned_by = excluded.returned_by,
		returned_reason = excluded.returned_reason, retest_source = excluded.retest_source, retest_result = excluded.retest_result,
		approved_hash = excluded.approved_hash, withdrawn_by = excluded.withdrawn_by, withdrawn_reason = excluded.withdrawn_reason`,
		eng, fid, s.Status, s.ReturnedBy, s.ReturnedReason, s.RetestSource, s.RetestResult, s.ApprovedHash, s.WithdrawnBy, s.WithdrawnReason)
	if err != nil {
		return err
	}
	if _, err := tx.Exec("DELETE FROM reviewers WHERE eng = ? AND fid = ?", eng, fid); err != nil {
		return err
	}
	for _, r := range s.Reviewers {
		var h any
		if r.ClearedHash != "" {
			h = r.ClearedHash
		}
		if _, err := tx.Exec("INSERT INTO reviewers(eng, fid, username, cleared_hash) VALUES (?, ?, ?, ?)", eng, fid, r.Name, h); err != nil {
			return err
		}
	}
	return nil
}

const msgCols = "fid, id, ts, username, text, section, reply, resolves, reopens, event"

func scanMsg(sc interface{ Scan(...any) error }) (string, chat.Message, error) {
	var fid, ts string
	var m chat.Message
	if err := sc.Scan(&fid, &m.ID, &ts, &m.User, &m.Text, &m.Section, &m.Reply, &m.Resolves, &m.Reopens, &m.Event); err != nil {
		return "", m, err
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	m.TS = t
	return fid, m, err
}

// Messages returns a finding's chat in posting order.
func (d *DB) Messages(eng, fid string) ([]chat.Message, error) { return findingMessages(d, eng, fid) }

// Messages reads a finding's chat inside the transaction (validate, then
// add, without a concurrent post slipping in between).
func (tx *Tx) Messages(eng, fid string) ([]chat.Message, error) { return findingMessages(tx, eng, fid) }

func findingMessages(q querier, eng, fid string) ([]chat.Message, error) {
	all, err := messages(q, "SELECT "+msgCols+" FROM chat WHERE eng = ? AND fid = ? ORDER BY seq", eng, fid)
	return all[fid], err
}

// ChatStamp identifies a finding's chat without reading it: the number of
// messages and the highest message sequence number ("<n>.<seq>"). Any post,
// workflow event or purge changes it.
func (d *DB) ChatStamp(eng, fid string) (string, error) {
	var n, seq int64
	err := d.QueryRow("SELECT COUNT(*), COALESCE(MAX(seq), 0) FROM chat WHERE eng = ? AND fid = ?", eng, fid).Scan(&n, &seq)
	return strconv.FormatInt(n, 10) + "." + strconv.FormatInt(seq, 10), err
}

// AllMessages returns every finding's chat in an engagement, by finding ID.
func (d *DB) AllMessages(eng string) (map[string][]chat.Message, error) {
	return messages(d, "SELECT "+msgCols+" FROM chat WHERE eng = ? ORDER BY seq", eng)
}

func messages(d querier, q string, args ...any) (map[string][]chat.Message, error) {
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]chat.Message{}
	for rows.Next() {
		fid, m, err := scanMsg(rows)
		if err != nil {
			return nil, err
		}
		out[fid] = append(out[fid], m)
	}
	return out, rows.Err()
}

// SetChatHidden hides (on) or shows a chat thread of a finding for one user.
// It is a personal view setting: no change counter moves.
func (d *DB) SetChatHidden(user, eng, fid, thread string, on bool) error {
	q := "DELETE FROM chat_hidden WHERE username = ? AND eng = ? AND fid = ? AND thread_id = ?"
	if on {
		q = "INSERT OR IGNORE INTO chat_hidden(username, eng, fid, thread_id) VALUES (?, ?, ?, ?)"
	}
	_, err := d.Exec(q, user, eng, fid, thread)
	return err
}

// ChatHidden returns the threads of a finding that user hid.
func (d *DB) ChatHidden(user, eng, fid string) (map[string]bool, error) {
	rows, err := d.Query("SELECT thread_id FROM chat_hidden WHERE username = ? AND eng = ? AND fid = ?", user, eng, fid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// AddMessage appends a chat message (or workflow event) to a finding.
func (tx *Tx) AddMessage(eng, fid string, m chat.Message) error {
	tx.touch(eng)
	_, err := tx.Exec("INSERT INTO chat(id, eng, fid, ts, username, text, section, reply, resolves, reopens, event) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		m.ID, eng, fid, m.TS.UTC().Format(time.RFC3339Nano), m.User, m.Text, m.Section, m.Reply, m.Resolves, m.Reopens, m.Event)
	return err
}
