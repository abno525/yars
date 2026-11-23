package db

import (
	"os"
	"path/filepath"
	"testing"
)

// A data folder may have #, ? or % in its path. The database is opened
// through a file: URI, where # starts a fragment, ? a query and % an escape:
// unescaped, SQLite opened a file at the path cut short there, without the
// settings that follow it (WAL, foreign keys, the busy timeout).
func TestOpenPathWithURICharacters(t *testing.T) {
	for label, name := range map[string]string{"hash": "team#1", "question": "what?", "percent": "100%", "space": "a b"} {
		// a plain subtest name: the test's own temp dir has none of these
		t.Run(label, func(t *testing.T) {
			base := t.TempDir()
			path := filepath.Join(base, name, "yars.db")
			d, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			if _, err := d.Exec("CREATE TABLE probe(x)"); err != nil {
				t.Fatal(err)
			}
			var file string
			if err := d.QueryRow("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&file); err != nil {
				t.Fatal(err)
			}
			if file != path {
				t.Errorf("opened %q, want %q", file, path)
			}
			var mode string
			var fk, busy int64
			d.QueryRow("PRAGMA journal_mode").Scan(&mode)
			d.QueryRow("PRAGMA foreign_keys").Scan(&fk)
			d.QueryRow("PRAGMA busy_timeout").Scan(&busy)
			if mode != "wal" || fk != 1 || busy != 5000 {
				t.Errorf("journal_mode %q, foreign_keys %d, busy_timeout %d", mode, fk, busy)
			}
			// SchemaOf reads the same file
			if v, err := SchemaOf(path); err != nil || v == 0 {
				t.Errorf("SchemaOf: %d %v", v, err)
			}
			entries, _ := os.ReadDir(base)
			if len(entries) != 1 || entries[0].Name() != name {
				t.Errorf("files beside the folder: %v", entries)
			}
		})
	}
}
