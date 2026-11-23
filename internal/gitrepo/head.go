package gitrepo

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
)

var spawned atomic.Int64

// Spawned is the number of git processes started so far (for tests that
// check a code path starts none).
func Spawned() int64 { return spawned.Load() }

// gitDirs finds the git directory of the work tree at dir (a .git folder, or
// a .git file naming it) and the common directory that holds shared refs.
func gitDirs(dir string) (gitDir, common string, err error) {
	gd := filepath.Join(dir, ".git")
	info, err := os.Lstat(gd)
	if err != nil {
		return "", "", err
	}
	switch {
	case info.IsDir():
	case info.Mode().IsRegular():
		b, err := os.ReadFile(gd)
		if err != nil {
			return "", "", err
		}
		p, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir: ")
		if !ok {
			return "", "", fmt.Errorf("%s: not a gitdir file", gd)
		}
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		gd = p
	default:
		return "", "", fmt.Errorf("%s: not a git directory", gd)
	}
	common = gd
	if b, err := os.ReadFile(filepath.Join(gd, "commondir")); err == nil {
		c := strings.TrimSpace(string(b))
		if !filepath.IsAbs(c) {
			c = filepath.Join(gd, c)
		}
		common = c
	}
	return gd, common, nil
}

func isHash(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ReadHead returns the commit HEAD points to in the work tree at dir ("" for
// a branch with no commits yet), reading .git/HEAD and the ref (loose or
// packed) directly: no git process is started.
func ReadHead(dir string) (string, error) {
	gd, common, err := gitDirs(dir)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(filepath.Join(gd, "HEAD"))
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	for range 5 { // follow symbolic refs a few levels deep
		ref, ok := strings.CutPrefix(v, "ref: ")
		if !ok {
			if isHash(v) {
				return v, nil
			}
			return "", fmt.Errorf("%s: unexpected HEAD %q", dir, v)
		}
		ref = strings.TrimSpace(ref)
		if !strings.HasPrefix(ref, "refs/") || path.Clean(ref) != ref || strings.Contains(ref, "..") {
			return "", fmt.Errorf("%s: bad ref %q", dir, ref)
		}
		if v, err = readRef(gd, common, ref); err != nil || v == "" {
			return "", err
		}
	}
	return "", fmt.Errorf("%s: symbolic ref loop", dir)
}

// readRef reads one ref: the loose file (per-worktree, then common), then
// packed-refs. "" means the ref does not exist.
func readRef(gd, common, ref string) (string, error) {
	for _, d := range []string{gd, common} {
		b, err := os.ReadFile(filepath.Join(d, filepath.FromSlash(ref)))
		if err == nil {
			return strings.TrimSpace(string(b)), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	b, err := os.ReadFile(filepath.Join(common, "packed-refs"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if h, name, ok := strings.Cut(line, " "); ok && name == ref && isHash(h) {
			return h, nil
		}
	}
	return "", sc.Err()
}

// CommitGitlinks sets submodule pointers (path -> commit) in the index and
// commits them as a. Unlike Commit it never reads the nested repos, so a
// nested repo moving meanwhile can't leave a different pointer staged.
// Callers must hold whatever serializes writes to this repo's index.
func (r *Repo) CommitGitlinks(links map[string]string, msg string, a Author) error {
	args := []string{"update-index", "--add"}
	for _, p := range slices.Sorted(maps.Keys(links)) {
		if !isHash(links[p]) {
			return fmt.Errorf("gitlink %s: bad commit %q", p, links[p])
		}
		args = append(args, "--cacheinfo", "160000,"+links[p]+","+p)
	}
	if _, err := r.run(nil, args...); err != nil {
		return err
	}
	env := []string{"GIT_AUTHOR_NAME=" + a.Name, "GIT_AUTHOR_EMAIL=" + a.Email, "GIT_COMMITTER_NAME=" + a.Name, "GIT_COMMITTER_EMAIL=" + a.Email}
	if _, err := r.run(env, "commit", "-q", "-m", msg); err != nil {
		r.Unstage(slices.Collect(maps.Keys(links)))
		return err
	}
	return nil
}

// Gitlinks returns the submodule pointers directly under dir at rev, by
// entry name, in one git process. A repo with no commits has none.
func (r *Repo) Gitlinks(rev, dir string) (map[string]string, error) {
	out := map[string]string{}
	if h, err := ReadHead(r.Dir); err == nil && h == "" {
		return out, nil
	}
	s, err := r.run(nil, "ls-tree", "-z", rev, strings.TrimSuffix(dir, "/")+"/")
	if err != nil {
		return nil, err
	}
	for _, e := range strings.Split(strings.TrimSuffix(s, "\x00"), "\x00") {
		meta, name, ok := strings.Cut(e, "\t")
		f := strings.Fields(meta)
		if ok && len(f) == 3 && f[0] == "160000" && f[1] == "commit" {
			out[path.Base(name)] = f[2]
		}
	}
	return out, nil
}
