// Package db is YARS's SQLite store for everything that is not finding
// content: accounts, API tokens, sessions, workflow state and chat.
package db

import (
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	_ "modernc.org/sqlite"
)

// Path is where the database lives inside a data directory (git-ignored).
func Path(dataDir string) string { return filepath.Join(dataDir, ".yars", "yars.db") }

const schemaVersion = 4

var migrations = []string{
	// v1
	`CREATE TABLE users (
		username      TEXT PRIMARY KEY,
		email         TEXT NOT NULL DEFAULT '',
		role          TEXT NOT NULL,
		password_hash TEXT NOT NULL DEFAULT '',
		created       TEXT NOT NULL
	);
	CREATE TABLE tokens (
		hash     TEXT PRIMARY KEY,
		username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
		created  TEXT NOT NULL
	);
	CREATE TABLE sessions (
		hash      TEXT PRIMARY KEY,
		username  TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
		created   TEXT NOT NULL,
		last_seen TEXT NOT NULL
	);
	CREATE TABLE finding_state (
		eng             TEXT NOT NULL,
		fid             TEXT NOT NULL,
		status          TEXT NOT NULL DEFAULT 'draft',
		returned_by     TEXT NOT NULL DEFAULT '',
		returned_reason TEXT NOT NULL DEFAULT '',
		retest_source   TEXT NOT NULL DEFAULT '',
		retest_result   TEXT NOT NULL DEFAULT '',
		approved_hash   TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (eng, fid)
	);
	CREATE TABLE reviewers (
		eng          TEXT NOT NULL,
		fid          TEXT NOT NULL,
		username     TEXT NOT NULL,
		cleared_hash TEXT,
		PRIMARY KEY (eng, fid, username)
	);
	CREATE TABLE chat (
		seq      INTEGER PRIMARY KEY AUTOINCREMENT,
		id       TEXT NOT NULL UNIQUE,
		eng      TEXT NOT NULL,
		fid      TEXT NOT NULL,
		ts       TEXT NOT NULL,
		username TEXT NOT NULL,
		text     TEXT NOT NULL DEFAULT '',
		section  TEXT NOT NULL DEFAULT '',
		reply    TEXT NOT NULL DEFAULT '',
		resolves TEXT NOT NULL DEFAULT '',
		reopens  TEXT NOT NULL DEFAULT '',
		event    TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX chat_finding ON chat(eng, fid, seq);
	CREATE TABLE changes (id INTEGER PRIMARY KEY CHECK (id = 1), seq INTEGER NOT NULL);
	INSERT INTO changes VALUES (1, 0);`,
	// v2: a change counter per engagement, so readers rebuild only what moved
	`CREATE TABLE changes_eng (eng TEXT PRIMARY KEY, seq INTEGER NOT NULL) WITHOUT ROWID;`,
	// v3: withdrawn findings (who and why) and resolved chat threads a user
	// chose to hide
	`ALTER TABLE finding_state ADD COLUMN withdrawn_by TEXT NOT NULL DEFAULT '';
	ALTER TABLE finding_state ADD COLUMN withdrawn_reason TEXT NOT NULL DEFAULT '';
	CREATE TABLE chat_hidden (
		username  TEXT NOT NULL,
		eng       TEXT NOT NULL,
		fid       TEXT NOT NULL,
		thread_id TEXT NOT NULL,
		PRIMARY KEY (username, eng, fid, thread_id)
	) WITHOUT ROWID;`,
	// v4: check runs with their results, dismissed violations, and chat
	// threads opened by YARS (kind = check)
	`ALTER TABLE chat ADD COLUMN kind TEXT NOT NULL DEFAULT '';
	CREATE TABLE check_runs (
		id           INTEGER PRIMARY KEY,
		eng          TEXT NOT NULL,
		fid          TEXT NOT NULL,
		content_hash TEXT NOT NULL,
		started      TEXT NOT NULL,
		finished     TEXT NOT NULL DEFAULT '',
		state        TEXT NOT NULL,
		by_user      TEXT NOT NULL,
		total        INTEGER NOT NULL DEFAULT 0,
		done_count   INTEGER NOT NULL DEFAULT 0,
		error        TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX check_runs_finding ON check_runs(eng, fid, id);
	CREATE TABLE check_results (
		run_id     INTEGER NOT NULL REFERENCES check_runs(id) ON DELETE CASCADE,
		rule       TEXT NOT NULL,
		level      TEXT NOT NULL,
		message    TEXT NOT NULL,
		target     TEXT NOT NULL,
		quote      TEXT NOT NULL DEFAULT '',
		quote_hash TEXT NOT NULL DEFAULT '',
		thread     TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX check_results_run ON check_results(run_id);
	CREATE TABLE dismissals (
		eng        TEXT NOT NULL,
		fid        TEXT NOT NULL,
		rule       TEXT NOT NULL,
		quote_hash TEXT NOT NULL,
		level      TEXT NOT NULL,
		by_user    TEXT NOT NULL,
		at         TEXT NOT NULL,
		PRIMARY KEY (eng, fid, rule, quote_hash)
	) WITHOUT ROWID;`,
}

type DB struct {
	*sql.DB
	now func() time.Time
}

// Open opens (creating if needed) the database at path and brings the schema
// up to date. The file and its WAL companions are private (0600).
func Open(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600); err != nil {
		return nil, err
	} else {
		f.Close()
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)&_pragma=cache_size(-20000)&_pragma=mmap_size(134217728)&_txlock=immediate"
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	sdb.SetMaxOpenConns(8)
	d := &DB{DB: sdb, now: time.Now}
	if err := d.migrate(); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Stat(p); err == nil {
			os.Chmod(p, 0o600)
		}
	}
	return d, nil
}

func (d *DB) migrate() error {
	var v int
	if err := d.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v > schemaVersion {
		return fmt.Errorf("database schema %d is newer than this yars (%d)", v, schemaVersion)
	}
	for ; v < schemaVersion; v++ {
		tx, err := d.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Tx is a write transaction; every one bumps the global change counter, and
// the counter of each engagement whose state or chat it writes.
type Tx struct {
	*sql.Tx
	touched map[string]bool
}

// touch marks eng as changed by this transaction.
func (tx *Tx) touch(eng string) {
	if tx.touched == nil {
		tx.touched = map[string]bool{}
	}
	tx.touched[eng] = true
}

// Tx runs fn in one write transaction and bumps the change counters, so
// readers (the index, chat polling) can tell that something changed.
func (d *DB) Tx(fn func(*Tx) error) error {
	_, err := d.tx("", fn)
	return err
}

// TxFor is Tx for a change to engagement eng: its own counter is bumped
// even when fn writes nothing of it.
func (d *DB) TxFor(eng string, fn func(*Tx) error) error {
	_, err := d.TxForSeq(eng, fn)
	return err
}

// TxForSeq is TxFor that also returns the engagement's counter after the
// commit.
func (d *DB) TxForSeq(eng string, fn func(*Tx) error) (int64, error) {
	if eng == "" {
		return 0, errors.New("TxFor: no engagement")
	}
	return d.tx(eng, fn)
}

func (d *DB) tx(eng string, fn func(*Tx) error) (int64, error) {
	stx, err := d.Begin()
	if err != nil {
		return 0, err
	}
	tx := &Tx{Tx: stx}
	if eng != "" {
		tx.touch(eng)
	}
	fail := func(err error) (int64, error) {
		stx.Rollback()
		return 0, err
	}
	if err := fn(tx); err != nil {
		return fail(err)
	}
	if _, err := stx.Exec("UPDATE changes SET seq = seq + 1 WHERE id = 1"); err != nil {
		return fail(err)
	}
	var seq int64
	for _, e := range slices.Sorted(maps.Keys(tx.touched)) {
		var s int64
		if err := stx.QueryRow(`INSERT INTO changes_eng(eng, seq) VALUES (?, 1)
			ON CONFLICT(eng) DO UPDATE SET seq = seq + 1 RETURNING seq`, e).Scan(&s); err != nil {
			return fail(err)
		}
		if e == eng {
			seq = s
		}
	}
	return seq, stx.Commit()
}

// Seq is the global change counter.
func (d *DB) Seq() (int64, error) {
	var s int64
	err := d.QueryRow("SELECT seq FROM changes WHERE id = 1").Scan(&s)
	return s, err
}

// SeqFor is an engagement's change counter (0 when it never changed).
func (d *DB) SeqFor(eng string) (int64, error) {
	var s int64
	err := d.QueryRow("SELECT seq FROM changes_eng WHERE eng = ?", eng).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return s, err
}

// EngSeqs returns every engagement's change counter (one query).
func (d *DB) EngSeqs() (map[string]int64, error) {
	rows, err := d.Query("SELECT eng, seq FROM changes_eng")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var e string
		var s int64
		if err := rows.Scan(&e, &s); err != nil {
			return nil, err
		}
		out[e] = s
	}
	return out, rows.Err()
}

var ErrNotFound = errors.New("not found")

func (d *DB) stamp() string { return d.now().UTC().Format(time.RFC3339) }
