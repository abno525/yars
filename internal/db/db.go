// Package db is YARS's SQLite store for everything that is not finding
// content: accounts, API tokens, sessions, workflow state and chat.
package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Path is where the database lives inside a data directory (git-ignored).
func Path(dataDir string) string { return filepath.Join(dataDir, ".yars", "yars.db") }

const schemaVersion = 1

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
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate"
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
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

// Tx is a write transaction; every one bumps the change counter.
type Tx struct{ *sql.Tx }

// Tx runs fn in one write transaction and bumps the change counter, so
// readers (the index, chat polling) can tell that something changed.
func (d *DB) Tx(fn func(*Tx) error) error {
	stx, err := d.Begin()
	if err != nil {
		return err
	}
	tx := &Tx{stx}
	if err := fn(tx); err != nil {
		stx.Rollback()
		return err
	}
	if _, err := stx.Exec("UPDATE changes SET seq = seq + 1 WHERE id = 1"); err != nil {
		stx.Rollback()
		return err
	}
	return stx.Commit()
}

// Seq is the change counter.
func (d *DB) Seq() (int64, error) {
	var s int64
	err := d.QueryRow("SELECT seq FROM changes WHERE id = 1").Scan(&s)
	return s, err
}

var ErrNotFound = errors.New("not found")

func (d *DB) stamp() string { return d.now().UTC().Format(time.RFC3339) }
