package backup

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
)

// Report says what a backup holds.
type Report struct {
	Schema      int  // of the database in the backup
	Engagements int  // engagements/<id> that are repositories
	Findings    int  // findings/<dir>/finding.md files, in the restored folder
	HasKey      bool // .yars/secret.key is in the backup
	// PointInTime: every repository is at the commit it had when the
	// database snapshot was taken. A backup that records no commits (one an
	// earlier YARS wrote) is not.
	PointInTime bool
	// NotReset names the repositories left as they were unpacked, because
	// the backup records no usable commit for them: "main" and engagement
	// IDs, ", " between. "" when PointInTime, and for a backup that records
	// no commits at all.
	NotReset string
}

// ErrNewer refuses a backup whose database a newer YARS wrote.
var ErrNewer = errors.New("backup from a newer YARS")

const dbEntry = ".yars/yars.db"

// Restore unpacks zipPath into destDir (missing or empty), resets every
// repository to the commit the backup records for it, and verifies the
// result: the database opens and passes quick_check, and every repository
// passes git fsck. Nothing is written before every entry is known to be a
// plain file or folder inside the data folder and the database is not newer
// than this build; on a failure after unpacking, destDir is as it was
// before. A repository the backup records no usable commit for stays as
// unpacked and is named in the report; that never fails the restore.
func Restore(zipPath, destDir string) (Report, error) {
	var rep Report
	existed := false
	if fi, err := os.Stat(destDir); err == nil {
		if !fi.IsDir() {
			return rep, fmt.Errorf("%s is a file; restore into a new folder", destDir)
		}
		ents, err := os.ReadDir(destDir)
		if err != nil {
			return rep, err
		}
		if len(ents) > 0 {
			return rep, fmt.Errorf("%s is not empty; restore into a new folder", destDir)
		}
		existed = true
	} else if !os.IsNotExist(err) {
		return rep, err
	}

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return rep, err
	}
	defer zr.Close()
	var dbFile, metaFile *zip.File
	var lay gitLayout
	for _, f := range zr.File {
		lay.note(f.Name, f.Mode().IsDir())
		if !plain(f) {
			return rep, fmt.Errorf("%s: not a plain file inside the data folder", f.Name)
		}
		name := strings.TrimSuffix(f.Name, "/")
		// a .git file names another folder as the repository
		if part, ok := gitPart(name); ok && len(part) == 0 && !f.Mode().IsDir() {
			return rep, fmt.Errorf("%s: .git must be a folder", f.Name)
		}
		isMeta := name == metaEntry && !f.Mode().IsDir()
		if name != dbEntry && !isMeta && Skip(name, true) {
			return rep, fmt.Errorf("%s: not part of a backup", f.Name)
		}
		switch {
		case name == dbEntry && !f.Mode().IsDir():
			dbFile = f
		case isMeta && metaFile == nil:
			metaFile = f
		case name == ".yars/secret.key":
			rep.HasKey = true
		}
	}
	if dbFile == nil {
		return rep, fmt.Errorf("%s holds no %s; it is not a YARS backup", zipPath, dbEntry)
	}
	if err := lay.refuse(); err != nil {
		return rep, err
	}
	if rep.Schema, err = schemaIn(dbFile); err != nil {
		return rep, fmt.Errorf("%s: %w", dbEntry, err)
	}
	if rep.Schema > db.SchemaVersion {
		return rep, fmt.Errorf("%w (schema %d, this yars writes %d); upgrade yars first", ErrNewer, rep.Schema, db.SchemaVersion)
	}

	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return rep, err
	}
	undo := func() {
		if !existed {
			os.RemoveAll(destDir)
			return
		}
		ents, _ := os.ReadDir(destDir)
		for _, e := range ents {
			os.RemoveAll(filepath.Join(destDir, e.Name()))
		}
	}
	if err := unpack(zr.File, destDir); err != nil {
		undo()
		return rep, err
	}
	// after unpack, which dropped the hooks and wrote the git configs again:
	// git runs nothing of the ZIP's
	if m, ok := readMeta(metaFile); ok {
		left, err := rewind(destDir, m)
		if err != nil {
			undo()
			return rep, err
		}
		rep.PointInTime, rep.NotReset = len(left) == 0, strings.Join(left, ", ")
	}
	n, err := check(destDir)
	if err != nil {
		undo()
		return rep, err
	}
	rep.Engagements, rep.Findings = n, countFindings(destDir)
	return rep, nil
}

// readMeta reads the commits a backup records. A backup without the entry
// (an earlier YARS wrote it), and an entry that does not read, record none.
func readMeta(f *zip.File) (meta, bool) {
	var m meta
	if f == nil {
		return m, false
	}
	rc, err := f.Open()
	if err != nil {
		return m, false
	}
	b, err := io.ReadAll(io.LimitReader(rc, maxMeta+1))
	rc.Close()
	if err != nil || len(b) > maxMeta || json.Unmarshal(b, &m) != nil || m.Version != 1 {
		return meta{}, false
	}
	return m, true
}

// rewind resets the unpacked main repository and every unpacked engagement
// repository to the commit m records for it, and returns the ones it left as
// they were: "main", engagement IDs. The folders on disk are looked up in m;
// a name m holds never becomes a path. An error is a reset that failed part
// way.
func rewind(dest string, m meta) ([]string, error) {
	var left []string
	ok, err := rewindRepo(dest, m.Main, true)
	if err != nil {
		return nil, fmt.Errorf("main repository: %w", err)
	}
	if !ok {
		left = append(left, "main")
	}
	ents, err := os.ReadDir(filepath.Join(dest, "engagements"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range ents {
		dir := filepath.Join(dest, "engagements", e.Name())
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
			continue
		}
		commit, recorded := m.Engagements[e.Name()]
		ok, err := rewindRepo(dir, commit, recorded)
		if err != nil {
			return nil, fmt.Errorf("engagements/%s: %w", e.Name(), err)
		}
		if !ok {
			left = append(left, shownName(e.Name()))
		}
	}
	return left, nil
}

// rewindRepo resets the repository at dir to commit and reports whether it
// is now where the backup recorded it. It is left alone, and false, when
// nothing is recorded for it, when commit is not a commit id, and when the
// commit is not in the unpacked branch's history (a history rewritten while
// the backup was taken, or a ZIP put together by hand). A repository
// recorded without a commit ("") is right when it still has none.
func rewindRepo(dir, commit string, recorded bool) (bool, error) {
	if !recorded {
		return false, nil
	}
	if commit == "" {
		h, err := gitrepo.ReadHead(dir)
		return err == nil && h == "", nil
	}
	if !gitrepo.IsCommitID(commit) {
		return false, nil
	}
	// unpacked at that commit: nothing to reset
	if h, err := gitrepo.ReadHead(dir); err == nil && h == commit {
		return true, nil
	}
	r, err := gitrepo.Open(dir)
	if err != nil || !r.InHistory(commit) {
		return false, nil // not a repository root: check says so
	}
	if err := r.ResetTo(commit); err != nil {
		return false, err
	}
	return true, nil
}

// shownName is a folder name of an uploaded ZIP as a report shows it: an
// engagement ID's characters only, else "?".
func shownName(s string) string {
	if s == "" || len(s) > 64 {
		return "?"
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return "?"
		}
	}
	return s
}

// countFindings counts engagements/<id>/findings/<dir>/finding.md in the
// restored folder.
func countFindings(dest string) int {
	n := 0
	engs, _ := os.ReadDir(filepath.Join(dest, "engagements"))
	for _, e := range engs {
		if !e.IsDir() {
			continue
		}
		dirs, _ := os.ReadDir(filepath.Join(dest, "engagements", e.Name(), "findings"))
		for _, d := range dirs {
			if !d.IsDir() {
				continue
			}
			if fi, err := os.Lstat(filepath.Join(dest, "engagements", e.Name(), "findings", d.Name(), "finding.md")); err == nil && fi.Mode().IsRegular() {
				n++
			}
		}
	}
	return n
}

// Verify unpacks zipPath into a temporary folder, verifies it and removes
// it.
func Verify(zipPath string) (Report, error) {
	tmp, err := os.MkdirTemp("", "yars-verify-")
	if err != nil {
		return Report{}, err
	}
	defer os.RemoveAll(tmp)
	return Restore(zipPath, tmp)
}

// plain reports whether a ZIP entry is a regular file or a folder whose
// name stays inside the folder it is unpacked into.
func plain(f *zip.File) bool {
	m := f.Mode()
	if !m.IsRegular() && !m.IsDir() {
		return false
	}
	name := f.Name
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) || filepath.IsAbs(name) {
		return false
	}
	for _, seg := range strings.Split(strings.TrimSuffix(name, "/"), "/") {
		if seg == ".." || seg == "." || seg == "" {
			return false
		}
	}
	return true
}

// schemaIn reads the schema version of the database entry, copied to a
// temporary file.
func schemaIn(f *zip.File) (int, error) {
	tmp, err := os.CreateTemp("", "yars-restore-*.db")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())
	rc, err := f.Open()
	if err != nil {
		tmp.Close()
		return 0, err
	}
	_, err = io.Copy(tmp, rc)
	rc.Close()
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	return db.SchemaOf(tmp.Name())
}

// maxGitConfig is the most a ZIP's git config is read for its settings.
const maxGitConfig = 1 << 20

// unpack writes every entry under dest, for the owner alone: folders 0700,
// files with the owner's bits of the ZIP's mode (so a script stays one) and
// none for the group or others, whatever the backed-up folder had. Of a git
// folder it leaves the hooks out and writes the config again from its kept
// settings (gitconfig.go), so nothing unpacked makes git run a program.
func unpack(files []*zip.File, dest string) error {
	for _, f := range files {
		if f.Name == metaEntry {
			continue // read by Restore; never a file of the data folder
		}
		target := filepath.Join(dest, filepath.FromSlash(path.Clean(f.Name)))
		part, inGit := gitPart(f.Name)
		if inGit && gitDropped(part) {
			continue
		}
		if inGit && len(part) == 1 && part[0] == "config" && !f.Mode().IsDir() {
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("%s: %w", f.Name, err)
			}
			b, err := io.ReadAll(io.LimitReader(rc, maxGitConfig))
			rc.Close()
			if err != nil {
				return fmt.Errorf("%s: %w", f.Name, err)
			}
			if err := os.WriteFile(target, cleanGitConfig(b), 0o600); err != nil {
				return err
			}
			continue
		}
		if f.Mode().IsDir() {
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		perm := f.Mode().Perm()&0o700 | 0o600
		if f.Name == dbEntry || f.Name == ".yars/secret.key" {
			perm = 0o600 // never executable
		}
		if err := extract(f, target, perm); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
	}
	return nil
}

func extract(f *zip.File, target string, perm os.FileMode) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, rc); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// check opens the restored database and checks every repository; it
// returns the number of engagement repositories.
func check(dest string) (int, error) {
	d, err := db.Open(filepath.Join(dest, filepath.FromSlash(dbEntry)))
	if err != nil {
		return 0, fmt.Errorf("database: %w", err)
	}
	res, err := d.Check()
	d.Close()
	if err != nil {
		return 0, fmt.Errorf("database: %w", err)
	}
	if res != "ok" {
		return 0, fmt.Errorf("database: quick_check: %s", res)
	}
	main, err := gitrepo.Open(dest)
	if err != nil {
		return 0, fmt.Errorf("main repository: %w", err)
	}
	if err := main.Fsck(); err != nil {
		return 0, fmt.Errorf("main repository: %w", err)
	}
	ents, err := os.ReadDir(filepath.Join(dest, "engagements"))
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		dir := filepath.Join(dest, "engagements", e.Name())
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
			continue
		}
		r, err := gitrepo.Open(dir)
		if err == nil {
			err = r.Fsck()
		}
		if err != nil {
			return 0, fmt.Errorf("engagements/%s: %w", e.Name(), err)
		}
		n++
	}
	return n, nil
}
