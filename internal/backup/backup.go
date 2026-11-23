// Package backup writes a data folder to a ZIP and turns a ZIP back into a
// data folder. The website's download, yars backup and yars restore all use
// it.
package backup

import (
	"archive/zip"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"yars/internal/db"
)

// Options says what a backup holds beyond the data.
type Options struct {
	WithKey bool // .yars/secret.key, which decrypts stored AI and personal keys and webhook secrets
}

// Locker is what Write holds while it copies a repository; nil copies without
// locks.
type Locker interface {
	LockMain() (unlock func())
	LockEngagement(id string) (unlock func())
}

// Skip reports files a backup leaves out: the live database and its side
// files (a snapshot goes in instead), the snapshots taken before migrations,
// git's lock files (a commit in progress; restored, they would stop every
// later commit) and, unless withKey, the secret key.
func Skip(rel string, withKey bool) bool {
	switch {
	case rel == ".yars/yars.db",
		strings.HasPrefix(rel, ".yars/yars.db-"),
		strings.HasPrefix(rel, ".yars/yars.db.before-"):
		return true
	case strings.HasSuffix(rel, ".lock") && (strings.HasPrefix(rel, ".git/") || strings.Contains(rel, "/.git/")):
		return true
	case rel == ".yars/secret.key":
		return !withKey
	}
	return false
}

// Write streams a ZIP of dataDir to w and returns the bytes written: the main
// repo (under the main lock), each engagements/<id> repo (under its lock, one
// at a time), then a snapshot of the database as .yars/yars.db. Only regular
// files and folders go in; links could point out of the data folder. File
// modes are kept, so hooks and rule scripts stay executable.
func Write(w io.Writer, dataDir string, d *db.DB, l Locker, o Options) (int64, error) {
	// a data folder reached through a link is walked where it is
	dataDir, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return 0, err
	}
	tmp, err := os.MkdirTemp("", "yars-backup-")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)
	snap := filepath.Join(tmp, "yars.db")
	if err := d.Snapshot(snap); err != nil {
		return 0, err
	}
	// private in the ZIP, as the live database is (VACUUM INTO makes 0644)
	if err := os.Chmod(snap, 0o600); err != nil {
		return 0, err
	}
	cw := &countWriter{w: w}
	zw := zip.NewWriter(cw)
	b := &writer{zw: zw, root: dataDir, withKey: o.WithKey}

	unlock := lockMain(l)
	err = b.walk(dataDir, true)
	unlock()
	if err != nil {
		return cw.n, err
	}
	var engs []os.DirEntry
	// a linked engagements folder is not followed, as the main walk does not
	if fi, err := os.Lstat(filepath.Join(dataDir, "engagements")); err == nil && fi.IsDir() {
		if engs, err = os.ReadDir(filepath.Join(dataDir, "engagements")); err != nil {
			return cw.n, err
		}
	}
	for _, e := range engs {
		if !e.IsDir() {
			continue
		}
		unlock := lockEngagement(l, e.Name())
		err = b.walk(filepath.Join(dataDir, "engagements", e.Name()), false)
		unlock()
		if err != nil {
			return cw.n, err
		}
	}
	info, err := os.Stat(snap)
	if err == nil {
		err = b.add(snap, ".yars/yars.db", info)
	}
	if err == nil {
		err = zw.Close()
	}
	return cw.n, err
}

func lockMain(l Locker) func() {
	if l == nil {
		return func() {}
	}
	return l.LockMain()
}

func lockEngagement(l Locker, id string) func() {
	if l == nil {
		return func() {}
	}
	return l.LockEngagement(id)
}

type writer struct {
	zw      *zip.Writer
	root    string
	withKey bool

	beforeInfo func(path string) // test hook: runs before an entry is read
}

// walk adds every folder and regular file under from. With main set, the
// engagement repos (folders under engagements/) are left for their own walk.
// A file or folder that is gone by the time it is read (git's temporary
// files, when the copy takes no lock) is left out.
func (b *writer) walk(from string, main bool) error {
	return filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && p != from {
				return nil
			}
			return err
		}
		rel, err := filepath.Rel(b.root, p)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if main && d.IsDir() && strings.HasPrefix(rel, "engagements/") {
			return fs.SkipDir
		}
		if Skip(rel, b.withKey) {
			return nil
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		if b.beforeInfo != nil {
			b.beforeInfo(p)
		}
		info, err := d.Info()
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			return b.dir(rel, info)
		}
		return b.add(p, rel, info)
	})
}

func (b *writer) dir(rel string, info fs.FileInfo) error {
	h, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	h.Name = rel + "/"
	_, err = b.zw.CreateHeader(h)
	return err
}

func (b *writer) add(src, rel string, info fs.FileInfo) error {
	h, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}
	h.Name, h.Method = rel, zip.Deflate
	f, err := os.Open(src)
	if os.IsNotExist(err) {
		return nil // removed since it was listed
	}
	if err != nil {
		return err
	}
	defer f.Close()
	out, err := b.zw.CreateHeader(h)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, f)
	return err
}

// countWriter counts the bytes written through it (the backup's size).
type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
