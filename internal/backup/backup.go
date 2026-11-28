// Package backup writes a data folder to a ZIP and turns a ZIP back into a
// data folder. The website's download, yars backup and yars restore all use
// it.
package backup

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
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
		rel == ".yars/yars.db.lock", // the lock file of yars serve: empty, made again at the next start
		strings.HasPrefix(rel, ".yars/yars.db-"),
		strings.HasPrefix(rel, ".yars/yars.db.before-"):
		return true
	case strings.HasSuffix(rel, ".lock") && (strings.HasPrefix(rel, ".git/") || strings.Contains(rel, "/.git/")):
		return true
	case rel == metaEntry:
		// Write makes this entry itself; a file of that name on disk is not it
		return true
	case rel == ".yars/secret.key":
		return !withKey
	}
	return false
}

// metaEntry is the ZIP entry that holds the commit each repository was at
// when the database snapshot was taken.
const metaEntry = ".yars/backup.json"

// maxMeta is the most of metaEntry a restore reads.
const maxMeta = 1 << 20

// meta is metaEntry: the main repository's HEAD and each engagement
// repository's, read just before the snapshot ("" for one without a commit).
// An engagement folder that is no repository has no entry.
type meta struct {
	Version     int               `json:"version"`
	Main        string            `json:"main"`
	Engagements map[string]string `json:"engagements"`
}

// Write streams a ZIP of dataDir to w and returns the bytes written: the main
// repo (under the main lock), each engagements/<id> repo (under its lock, one
// at a time), the commits they were at when the snapshot was taken
// (.yars/backup.json), then a snapshot of the database as .yars/yars.db. Only
// regular files and folders go in; links could point out of the data folder.
// File modes are kept, so rule scripts stay executable (git hooks are in the
// ZIP too; a restore leaves them out).
//
// The commits are read before the snapshot, and with them the list of
// engagement folders, the only ones copied. A commit that lands later is in
// the ZIP, and a restore resets its repository to the recorded one: the
// database is then never behind the files. A history rewritten meanwhile (a
// purge) no longer holds the recorded commit, and Write fails.
func Write(w io.Writer, dataDir string, d *db.DB, l Locker, o Options) (int64, error) {
	// a data folder reached through a link is walked where it is
	dataDir, err := filepath.EvalSymlinks(dataDir)
	if err != nil {
		return 0, err
	}
	heads := meta{Version: 1, Engagements: map[string]string{}}
	if heads.Main, err = gitrepo.ReadHead(dataDir); err != nil {
		return 0, fmt.Errorf("main repository: %w", err)
	}
	var engs []string
	// a linked engagements folder is not followed, as the main walk does not
	if fi, err := os.Lstat(filepath.Join(dataDir, "engagements")); err == nil && fi.IsDir() {
		ents, err := os.ReadDir(filepath.Join(dataDir, "engagements"))
		if err != nil {
			return 0, err
		}
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			engs = append(engs, e.Name())
			// a folder that is no repository, or one that does not read, is
			// copied as it is and has no commit recorded
			if h, err := gitrepo.ReadHead(filepath.Join(dataDir, "engagements", e.Name())); err == nil {
				heads.Engagements[e.Name()] = h
			}
		}
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
	err = stillHolds(dataDir, heads.Main, "main repository")
	if err == nil {
		err = b.walk(dataDir, true)
	}
	unlock()
	if err != nil {
		return cw.n, err
	}
	for _, id := range engs {
		dir := filepath.Join(dataDir, "engagements", id)
		unlock := lockEngagement(l, id)
		if _, serr := os.Lstat(dir); os.IsNotExist(serr) {
			// gone since it was listed (an engagement that could not be made)
			delete(heads.Engagements, id)
			unlock()
			continue
		}
		err = stillHolds(dir, heads.Engagements[id], "engagements/"+id)
		if err == nil {
			err = b.walk(dir, false)
		}
		unlock()
		if err != nil {
			return cw.n, err
		}
	}
	if err := b.writeMeta(heads); err != nil {
		return cw.n, err
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

// stillHolds checks, under the repository's lock and before it is copied,
// that the commit recorded for it is still in its history ("" is a
// repository that had no commit, or none recorded: nothing to check).
func stillHolds(dir, commit, name string) error {
	if commit == "" {
		return nil
	}
	// not moved since: nothing to ask git (a repository git cannot read is
	// still copied, and a restore says what is wrong with it)
	if h, err := gitrepo.ReadHead(dir); err == nil && h == commit {
		return nil
	}
	if !(&gitrepo.Repo{Dir: dir}).InHistory(commit) {
		return fmt.Errorf("%s: its history changed while the backup was taken (commit %.7s is no longer in it); take the backup again", name, commit)
	}
	return nil
}

// writeMeta writes metaEntry.
func (b *writer) writeMeta(m meta) error {
	js, err := json.Marshal(m)
	if err != nil {
		return err
	}
	h := &zip.FileHeader{Name: metaEntry, Method: zip.Deflate}
	h.SetMode(0o600)
	out, err := b.zw.CreateHeader(h)
	if err != nil {
		return err
	}
	_, err = out.Write(js)
	return err
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
