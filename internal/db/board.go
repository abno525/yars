package db

import (
	"database/sql"
	"errors"
	"slices"
	"strconv"
	"strings"
)

// The team board: an engagement's notes ("leads"), each with a timeline of
// messages and events. Board writes run in plain transactions that move no
// change counter: the board is not finding content, so the index and the
// finding pages have nothing to reload. Archived engagements are checked
// inside each write transaction.

// Kinds of timeline entry.
const (
	KindMsg      = "msg"      // a message (Markdown)
	KindState    = "state"    // the state changed; Text is the new state
	KindDismiss  = "dismiss"  // dismissed; Text is the reason
	KindSeverity = "severity" // the likely severity; Text is it ("" = unset)
	KindDup      = "dup"      // duplicate of; Text is L-… or F-… ("" = cleared)
	KindFinding  = "finding"  // made into a finding; Text is its ID
)

// pendingFinding marks a note whose Make finding is under way.
const pendingFinding = "pending"

var (
	// ErrBoardStale: the note is no longer in the state the request saw.
	ErrBoardStale = errors.New("the note changed meanwhile")
	// ErrBoardLocked: the note became a finding and is read only.
	ErrBoardLocked = errors.New("the note is a finding now (read only)")
)

// Note is one board note with its timeline's totals.
type Note struct {
	Eng                        string
	Num                        int
	Title, Host, Author, State string
	Severity, DupOf, Finding   string
	DismissReason, Created     string
	Replies                    int    // messages after the first
	Activity                   string // the newest entry's time
	Last                       int64  // the newest entry's seq
	Pending                    bool   // Make finding is under way (Finding is "")
}

// NoteMsg is one timeline entry.
type NoteMsg struct {
	Seq            int64
	TS, User, Kind string
	Text           string
}

// Unseen is a note with an entry by someone else that a user has not seen.
type Unseen struct {
	Eng                   string
	Num                   int
	Title, State, Finding string
	LastUser, LastKind    string
	LastText, LastTS      string
	Last                  int64
}

// boardTx runs fn in a write transaction that moves no change counter.
func (d *DB) boardTx(eng string, fn func(*Tx) error) error {
	stx, err := d.Begin()
	if err != nil {
		return err
	}
	tx := &Tx{Tx: stx, now: d.now}
	if a, err := tx.Archived(eng); err != nil || a {
		stx.Rollback()
		if err != nil {
			return err
		}
		return ErrArchived
	}
	if err := fn(tx); err != nil {
		stx.Rollback()
		return err
	}
	return stx.Commit()
}

// addEntry appends to a note's timeline; the writer has seen it.
func (tx *Tx) addEntry(eng string, num int, user, kind, text string) (int64, error) {
	var seq int64
	if err := tx.QueryRow("INSERT INTO board_messages(eng, num, ts, username, kind, text) VALUES (?, ?, ?, ?, ?, ?) RETURNING seq",
		eng, num, tx.stamp(), user, kind, text).Scan(&seq); err != nil {
		return 0, err
	}
	return seq, seeNote(tx, user, eng, num, seq)
}

type execer interface {
	Exec(string, ...any) (sql.Result, error)
}

func seeNote(e execer, user, eng string, num int, seq int64) error {
	_, err := e.Exec(`INSERT INTO board_seen(username, eng, num, seq) VALUES (?, ?, ?, ?)
		ON CONFLICT(username, eng, num) DO UPDATE SET seq = max(seq, excluded.seq)`, user, eng, num, seq)
	return err
}

// CreateNote adds a note to n.Eng's board with the next number and text as
// its first message.
func (d *DB) CreateNote(n Note, text string) (Note, error) {
	err := d.boardTx(n.Eng, func(tx *Tx) error {
		if err := tx.QueryRow("SELECT COALESCE(MAX(num), 0) + 1 FROM board_notes WHERE eng = ?", n.Eng).Scan(&n.Num); err != nil {
			return err
		}
		n.Created = tx.stamp()
		if _, err := tx.Exec(`INSERT INTO board_notes(eng, num, title, host, author, state, created) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			n.Eng, n.Num, n.Title, n.Host, n.Author, n.State, n.Created); err != nil {
			return err
		}
		_, err := tx.addEntry(n.Eng, n.Num, n.Author, KindMsg, text)
		return err
	})
	if err != nil {
		return Note{}, err
	}
	return d.Note(n.Eng, n.Num)
}

const boardCols = `n.eng, n.num, n.title, n.host, n.author, n.state, n.severity, n.dup_of, n.finding, n.dismiss_reason, n.created,
	COALESCE(SUM(m.kind = 'msg'), 1) - 1, COALESCE(MAX(m.ts), n.created), COALESCE(MAX(m.seq), 0)`

func scanBoardNote(sc interface{ Scan(...any) error }) (Note, error) {
	var n Note
	err := sc.Scan(&n.Eng, &n.Num, &n.Title, &n.Host, &n.Author, &n.State, &n.Severity, &n.DupOf, &n.Finding, &n.DismissReason, &n.Created,
		&n.Replies, &n.Activity, &n.Last)
	if n.Finding == pendingFinding {
		n.Finding, n.Pending = "", true
	}
	return n, err
}

// Note returns one note of eng.
func (d *DB) Note(eng string, num int) (Note, error) {
	n, err := scanBoardNote(d.QueryRow(`SELECT `+boardCols+` FROM board_notes n
		LEFT JOIN board_messages m ON m.eng = n.eng AND m.num = n.num
		WHERE n.eng = ? AND n.num = ? GROUP BY n.eng, n.num`, eng, num))
	if errors.Is(err, sql.ErrNoRows) {
		return Note{}, ErrNotFound
	}
	return n, err
}

// NoteFilter picks notes: one state ("" = all) and text in the title or
// host ("" = any), at most Limit (0 = no limit).
type NoteFilter struct {
	State, Q string
	Limit    int
}

// likeEscape makes s match itself in a LIKE … ESCAPE '\' pattern.
func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// Notes returns eng's notes that f picks, the latest activity first (one
// query).
func (d *DB) Notes(eng string, f NoteFilter) ([]Note, error) {
	q, args := `SELECT `+boardCols+` FROM board_notes n
		LEFT JOIN board_messages m ON m.eng = n.eng AND m.num = n.num
		WHERE n.eng = ?`, []any{eng}
	if f.State != "" {
		q, args = q+" AND n.state = ?", append(args, f.State)
	}
	if f.Q != "" {
		p := "%" + likeEscape(f.Q) + "%"
		q, args = q+` AND (n.title LIKE ? ESCAPE '\' OR n.host LIKE ? ESCAPE '\')`, append(args, p, p)
	}
	q += " GROUP BY n.eng, n.num ORDER BY MAX(m.seq) DESC, n.num DESC"
	if f.Limit > 0 {
		q, args = q+" LIMIT ?", append(args, f.Limit)
	}
	rows, err := d.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Note
	for rows.Next() {
		n, err := scanBoardNote(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// NoteCounts counts eng's notes by state.
func (d *DB) NoteCounts(eng string) (map[string]int, error) {
	rows, err := d.Query("SELECT state, count(*) FROM board_notes WHERE eng = ? GROUP BY state", eng)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return nil, err
		}
		out[s] = n
	}
	return out, rows.Err()
}

// NoteStamp identifies the state of eng's board (one cheap query): the
// newest timeline entry.
func (d *DB) NoteStamp(eng string) (int64, error) {
	var s int64
	err := d.QueryRow("SELECT COALESCE(MAX(seq), 0) FROM board_messages WHERE eng = ?", eng).Scan(&s)
	return s, err
}

// NoteMessages returns a note's timeline, oldest first: the first message
// and the newest limit-1 entries; older is how many are left out between.
func (d *DB) NoteMessages(eng string, num, limit int) ([]NoteMsg, int, error) {
	limit = max(limit, 2)
	scan := func(q string, args ...any) ([]NoteMsg, error) {
		rows, err := d.Query(q, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []NoteMsg
		for rows.Next() {
			var m NoteMsg
			if err := rows.Scan(&m.Seq, &m.TS, &m.User, &m.Kind, &m.Text); err != nil {
				return nil, err
			}
			out = append(out, m)
		}
		return out, rows.Err()
	}
	const cols = "SELECT seq, ts, username, kind, text FROM board_messages WHERE eng = ? AND num = ?"
	first, err := scan(cols+" ORDER BY seq LIMIT 1", eng, num)
	if err != nil || len(first) == 0 {
		return nil, 0, err
	}
	tail, err := scan(cols+" AND seq > ? ORDER BY seq DESC LIMIT ?", eng, num, first[0].Seq, limit-1)
	if err != nil {
		return nil, 0, err
	}
	slices.Reverse(tail)
	var total int
	if err := d.QueryRow("SELECT count(*) FROM board_messages WHERE eng = ? AND num = ?", eng, num).Scan(&total); err != nil {
		return nil, 0, err
	}
	return append(first, tail...), total - 1 - len(tail), nil
}

// open reads a note for a change inside tx: it must exist and have no
// finding.
func (tx *Tx) openNote(eng string, num int) (state, severity, dup string, err error) {
	var finding string
	err = tx.QueryRow("SELECT state, severity, dup_of, finding FROM board_notes WHERE eng = ? AND num = ?", eng, num).Scan(&state, &severity, &dup, &finding)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", ErrNotFound
	}
	if err == nil && finding != "" {
		err = ErrBoardLocked
	}
	return state, severity, dup, err
}

// PostNote adds user's message to a note without a finding.
func (d *DB) PostNote(eng string, num int, user, text string) (int64, error) {
	var seq int64
	err := d.boardTx(eng, func(tx *Tx) error {
		if _, _, _, err := tx.openNote(eng, num); err != nil {
			return err
		}
		var err error
		seq, err = tx.addEntry(eng, num, user, KindMsg, text)
		return err
	})
	return seq, err
}

// SetNoteState moves a note without a finding from state from (what the
// user saw; else ErrBoardStale) to state to. Dismissed keeps reason; any
// other state clears it. The event records who and when.
func (d *DB) SetNoteState(eng string, num int, user, from, to, reason string) error {
	return d.boardTx(eng, func(tx *Tx) error {
		cur, _, _, err := tx.openNote(eng, num)
		if err != nil {
			return err
		}
		if cur != from {
			return ErrBoardStale
		}
		kind, text := KindState, to
		if to == "dismissed" {
			kind, text = KindDismiss, reason
		} else {
			reason = ""
		}
		if _, err := tx.Exec("UPDATE board_notes SET state = ?, dismiss_reason = ? WHERE eng = ? AND num = ?", to, reason, eng, num); err != nil {
			return err
		}
		_, err = tx.addEntry(eng, num, user, kind, text)
		return err
	})
}

// SetNoteSeverity sets a note's likely severity ("" = unset).
func (d *DB) SetNoteSeverity(eng string, num int, user, sev string) error {
	return d.boardTx(eng, func(tx *Tx) error {
		_, cur, _, err := tx.openNote(eng, num)
		if err != nil || cur == sev {
			return err
		}
		if _, err := tx.Exec("UPDATE board_notes SET severity = ? WHERE eng = ? AND num = ?", sev, eng, num); err != nil {
			return err
		}
		_, err = tx.addEntry(eng, num, user, KindSeverity, sev)
		return err
	})
}

// SetNoteDup records what a note duplicates (L-… or F-… of the same
// engagement, checked by the caller; "" = nothing).
func (d *DB) SetNoteDup(eng string, num int, user, dup string) error {
	return d.boardTx(eng, func(tx *Tx) error {
		_, _, cur, err := tx.openNote(eng, num)
		if err != nil || cur == dup {
			return err
		}
		if _, err := tx.Exec("UPDATE board_notes SET dup_of = ? WHERE eng = ? AND num = ?", dup, eng, num); err != nil {
			return err
		}
		_, err = tx.addEntry(eng, num, user, KindDup, dup)
		return err
	})
}

// ClaimNote reserves a confirmed or info note without a finding for Make
// finding, so only one finding is made of it; LinkNote or UnclaimNote ends
// the claim.
func (d *DB) ClaimNote(eng string, num int) error {
	return d.boardTx(eng, func(tx *Tx) error {
		res, err := tx.Exec(`UPDATE board_notes SET finding = ? WHERE eng = ? AND num = ? AND finding = '' AND state IN ('confirmed', 'info')`,
			pendingFinding, eng, num)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return nil
		}
		if _, _, _, err := tx.openNote(eng, num); err != nil {
			return err
		}
		return ErrBoardStale
	})
}

// LinkNote ends a claim: the note now is finding fid (read only).
func (d *DB) LinkNote(eng string, num int, user, fid string) error {
	stx, err := d.Begin()
	if err != nil {
		return err
	}
	tx := &Tx{Tx: stx, now: d.now}
	res, err := tx.Exec("UPDATE board_notes SET finding = ? WHERE eng = ? AND num = ? AND finding = ?", fid, eng, num, pendingFinding)
	if err == nil {
		if n, _ := res.RowsAffected(); n != 1 {
			err = ErrBoardStale
		}
	}
	if err == nil {
		_, err = tx.addEntry(eng, num, user, KindFinding, fid)
	}
	if err != nil {
		stx.Rollback()
		return err
	}
	return stx.Commit()
}

// UnclaimNote gives a claim back (the finding could not be made).
func (d *DB) UnclaimNote(eng string, num int) error {
	_, err := d.Exec("UPDATE board_notes SET finding = '' WHERE eng = ? AND num = ? AND finding = ?", eng, num, pendingFinding)
	return err
}

// SeeNote records that user saw a note up to its newest entry. It is the
// user's own read state, so it is allowed on archived engagements too.
func (d *DB) SeeNote(user, eng string, num int) error {
	var seq int64
	if err := d.QueryRow("SELECT COALESCE(MAX(seq), 0) FROM board_messages WHERE eng = ? AND num = ?", eng, num).Scan(&seq); err != nil || seq == 0 {
		return err
	}
	return seeNote(d, user, eng, num, seq)
}

// unseenQuery finds, per note, the newest entry by someone other than ?1
// that ?1 has not seen. A team member follows every note of the team, from
// the time they joined; someone who sees the engagement without being on
// its team (a director, an admin) follows the notes they opened or wrote
// in, so no one is flooded with a whole board they never looked at.
const unseenQuery = `SELECT n.eng, n.num, n.title, n.state, n.finding, m.username, m.kind, m.text, m.ts, m.seq
	FROM board_notes n
	JOIN board_messages m ON m.seq = (SELECT MAX(x.seq) FROM board_messages x WHERE x.eng = n.eng AND x.num = n.num AND x.username != ?1)
	LEFT JOIN board_seen s ON s.username = ?1 AND s.eng = n.eng AND s.num = n.num
	LEFT JOIN engagement_members em ON em.eng = n.eng AND em.username = ?1
	WHERE m.seq > COALESCE(s.seq, 0)
	AND ((em.username IS NOT NULL AND (em.joined = '' OR m.ts >= em.joined)) OR s.seq IS NOT NULL)`

// UnseenNotes lists up to limit notes with something new to user, newest
// first, across every engagement; the caller keeps the ones user may see.
func (d *DB) UnseenNotes(user string, limit int) ([]Unseen, error) {
	rows, err := d.Query(unseenQuery+" ORDER BY m.seq DESC LIMIT ?2", user, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Unseen
	for rows.Next() {
		var u Unseen
		if err := rows.Scan(&u.Eng, &u.Num, &u.Title, &u.State, &u.Finding, &u.LastUser, &u.LastKind, &u.LastText, &u.LastTS, &u.Last); err != nil {
			return nil, err
		}
		if u.Finding == pendingFinding {
			u.Finding = ""
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UnseenIn lists up to limit notes with something new to user, newest
// first, of the engagements engs only, and how many there are in all. The
// engagement filter runs before the limit, so other engagements never take
// a slot.
func (d *DB) UnseenIn(user string, engs []string, limit int) ([]Unseen, int, error) {
	if len(engs) == 0 {
		return nil, 0, nil
	}
	args := []any{user, limit}
	ph := make([]string, len(engs))
	for i, e := range engs {
		args = append(args, e)
		ph[i] = "?" + strconv.Itoa(i+3)
	}
	q := unseenQuery + " AND n.eng IN (" + strings.Join(ph, ", ") + ")"
	var total int
	// the count names ?2 (the limit) too, so both statements take the same
	// numbered arguments
	if err := d.QueryRow("SELECT count(*) FROM ("+q+") WHERE ?2 = ?2", args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if total == 0 {
		return nil, 0, nil
	}
	rows, err := d.Query(q+" ORDER BY m.seq DESC LIMIT ?2", args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Unseen
	for rows.Next() {
		var u Unseen
		if err := rows.Scan(&u.Eng, &u.Num, &u.Title, &u.State, &u.Finding, &u.LastUser, &u.LastKind, &u.LastText, &u.LastTS, &u.Last); err != nil {
			return nil, 0, err
		}
		if u.Finding == pendingFinding {
			u.Finding = ""
		}
		out = append(out, u)
	}
	return out, total, rows.Err()
}

// UnseenCount is how many of eng's notes have something new to user.
func (d *DB) UnseenCount(user, eng string) (int, error) {
	var n int
	err := d.QueryRow("SELECT count(*) FROM ("+unseenQuery+" AND n.eng = ?2)", user, eng).Scan(&n)
	return n, err
}

// ResetBoardClaims gives back every Make finding claim. The server calls it
// once when it starts, before it takes requests: a claim then is one a stop
// cut off. (Other commands open the database while the server runs, so
// opening never does this.)
func (d *DB) ResetBoardClaims() error {
	_, err := d.Exec("UPDATE board_notes SET finding = '' WHERE finding = ?", pendingFinding)
	return err
}
