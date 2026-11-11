package backup

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"yars/internal/db"
	"yars/internal/gitrepo"
)

// Report says what a backup holds.
type Report struct {
	Schema      int  // of the database in the backup
	Engagements int  // engagements/<id> that are repositories
	Findings    int  // findings/<dir>/finding.md files
	HasKey      bool // .yars/secret.key is in the backup
}

// ErrNewer refuses a backup whose database a newer YARS wrote.
var ErrNewer = errors.New("backup from a newer YARS")

const dbEntry = ".yars/yars.db"

// Restore unpacks zipPath into destDir (missing or empty) and verifies it:
// the database opens and passes quick_check, and every repository passes
// git fsck. Nothing is written before every entry is known to be a plain
// file or folder inside the data folder and the database is not newer than
// this build; on a failure after unpacking, destDir is as it was before.
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
	var dbFile *zip.File
	for _, f := range zr.File {
		if !plain(f) {
			return rep, fmt.Errorf("%s: not a plain file inside the data folder", f.Name)
		}
		name := strings.TrimSuffix(f.Name, "/")
		if name != dbEntry && Skip(name, true) {
			return rep, fmt.Errorf("%s: not part of a backup", f.Name)
		}
		switch {
		case name == dbEntry && !f.Mode().IsDir():
			dbFile = f
		case name == ".yars/secret.key":
			rep.HasKey = true
		}
		if isFinding(name) && !f.Mode().IsDir() {
			rep.Findings++
		}
	}
	if dbFile == nil {
		return rep, fmt.Errorf("%s holds no %s; it is not a YARS backup", zipPath, dbEntry)
	}
	if rep.Schema, err = schemaIn(dbFile); err != nil {
		return rep, fmt.Errorf("%s: %w", dbEntry, err)
	}
	if rep.Schema > db.SchemaVersion {
		return rep, fmt.Errorf("%w (schema %d, this yars writes %d); upgrade yars first", ErrNewer, rep.Schema, db.SchemaVersion)
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
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
	n, err := check(destDir)
	if err != nil {
		undo()
		return rep, err
	}
	rep.Engagements = n
	return rep, nil
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

// isFinding reports whether name is engagements/<id>/findings/<dir>/finding.md.
func isFinding(name string) bool {
	segs := strings.Split(name, "/")
	return len(segs) == 5 && segs[0] == "engagements" && segs[2] == "findings" && segs[4] == "finding.md"
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

// unpack writes every entry under dest, keeping file modes.
func unpack(files []*zip.File, dest string) error {
	for _, f := range files {
		target := filepath.Join(dest, filepath.FromSlash(path.Clean(f.Name)))
		if f.Mode().IsDir() {
			if err := os.MkdirAll(target, f.Mode().Perm()|0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := extract(f, target); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
	}
	return nil
}

func extract(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.Mode().Perm())
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
