package main

import (
	"fmt"
	"path/filepath"
)

// dataLockPath is the file a yars serve holds its lock on (lockData). Its
// name is one the rules for the database already cover: git ignores it
// (.yars/yars.db*), a push cannot add it and a backup leaves it out.
func dataLockPath(dataDir string) string { return filepath.Join(dataDir, ".yars", "yars.db.lock") }

// errDataLocked is the answer of a yars serve on a data folder another
// yars serve runs on. It stops before anything is read or written.
func errDataLocked(dataDir string) error {
	return fmt.Errorf("another yars serve runs on this data folder (%s)", dataDir)
}
