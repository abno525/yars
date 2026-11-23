package store

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"yars/internal/gitrepo"
)

// SettingsFile is a file under .yars in the main repo (rules, exporters,
// templates, config). Data nil removes it; Exec makes it executable.
type SettingsFile struct {
	Path string
	Data []byte
	Exec bool
}

// settingsPath accepts clean paths under .yars, except the server's own
// files (database, accounts, tokens, keys), which never go into git.
func settingsPath(p string) bool {
	if p != path.Clean(p) || !strings.HasPrefix(p, ".yars/") {
		return false
	}
	switch name := strings.TrimPrefix(p, ".yars/"); {
	case strings.HasPrefix(name, "yars.db"), name == "users.yaml", name == "tokens.yaml", name == "secret.key":
		return false
	}
	return true
}

// EditSettings changes settings in the main repo with one commit as a,
// under the main repo's lock. fn reads the current files (read returns an
// fs.ErrNotExist error for a missing one) and returns the files to write.
// check, when not nil, runs once they are written and before the commit; if
// it or the commit fails, every file is restored and nothing is committed.
// fn's and check's errors are returned unchanged.
func (s *Store) EditSettings(msg string, a gitrepo.Author, fn func(read func(p string) ([]byte, error)) ([]SettingsFile, error), check func() error) error {
	if s.rootErr != nil {
		return s.rootErr
	}
	s.mainMu.Lock()
	defer s.mainMu.Unlock()
	read := func(p string) ([]byte, error) {
		if !settingsPath(p) {
			return nil, fmt.Errorf("%w: %s is not a settings file", ErrInvalidValue, p)
		}
		return s.readFile(p)
	}
	files, err := fn(read)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return nil
	}
	type before struct {
		data []byte // nil = did not exist
		mode fs.FileMode
	}
	prev := map[string]before{}
	var paths []string
	for _, f := range files {
		if !settingsPath(f.Path) {
			return fmt.Errorf("%w: %s is not a settings file", ErrInvalidValue, f.Path)
		}
		if _, dup := prev[f.Path]; dup {
			continue
		}
		var b before
		if info, err := s.root.Stat(f.Path); err == nil {
			if b.data, err = s.readFile(f.Path); err != nil {
				return err
			}
			if b.data == nil {
				b.data = []byte{}
			}
			b.mode = info.Mode().Perm()
		}
		prev[f.Path] = b
		paths = append(paths, f.Path)
	}
	restore := func() {
		s.repo.Unstage(paths)
		for _, p := range paths {
			b := prev[p]
			if b.data == nil {
				s.root.Remove(p)
				continue
			}
			s.writeFile(p, b.data)
			s.root.Chmod(p, b.mode)
		}
	}
	err = func() error {
		for _, f := range files {
			if f.Data == nil {
				if err := s.root.Remove(f.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
					return err
				}
				continue
			}
			if err := s.root.MkdirAll(path.Dir(f.Path), 0o755); err != nil {
				return err
			}
			if err := s.writeFile(f.Path, f.Data); err != nil {
				return err
			}
			if f.Exec {
				if err := s.root.Chmod(f.Path, 0o755); err != nil {
					return err
				}
			}
		}
		if check != nil {
			if err := check(); err != nil {
				return err
			}
		}
		err := s.repo.Commit(paths, msg, a)
		s.Invalidate("")
		return err
	}()
	if err != nil {
		restore()
		return err
	}
	if s.db != nil {
		s.db.Audit(a.Name, "settings", "", msg)
	}
	return nil
}
