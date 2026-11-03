// Package gitrepo is a thin wrapper around the git CLI.
package gitrepo

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Author struct {
	Name, Email string
}

// GitAuthor lets an Author act as a store actor (trusted, no role checks).
func (a Author) GitAuthor() Author { return a }

type Repo struct {
	Dir string
}

func (r *Repo) run(env []string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", r.Dir, "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// Open returns the repo whose work tree root is exactly dir.
func Open(dir string) (*Repo, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	r := &Repo{Dir: abs}
	top, err := r.run(nil, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, err
	}
	gotTop, _ := filepath.EvalSymlinks(strings.TrimSpace(top))
	wantTop, _ := filepath.EvalSymlinks(abs)
	if gotTop != wantTop {
		return nil, fmt.Errorf("%s is not a git repository root", dir)
	}
	return r, nil
}

// Init creates a repository in dir (branch main) if none exists, then opens it.
func Init(dir string) (*Repo, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); os.IsNotExist(err) {
		if out, err := exec.Command("git", "init", "-q", "-b", "main", dir).CombinedOutput(); err != nil {
			return nil, fmt.Errorf("git init: %w: %s", err, out)
		}
	}
	return Open(dir)
}

// Commit stages paths (relative to the repo root) and commits them as a.
func (r *Repo) Commit(paths []string, msg string, a Author) error {
	if _, err := r.run(nil, append([]string{"add", "-A", "--"}, paths...)...); err != nil {
		return err
	}
	env := []string{
		"GIT_AUTHOR_NAME=" + a.Name, "GIT_AUTHOR_EMAIL=" + a.Email,
		"GIT_COMMITTER_NAME=" + a.Name, "GIT_COMMITTER_EMAIL=" + a.Email,
	}
	// --only: commit exactly these paths, never anything else staged.
	_, err := r.run(env, append([]string{"commit", "-q", "--only", "-m", msg, "--"}, paths...)...)
	return err
}

// SetConfig sets a repository-local git config value.
func (r *Repo) SetConfig(key, value string) error {
	_, err := r.run(nil, "config", key, value)
	return err
}

// GitDir returns the absolute path of the .git directory.
func (r *Repo) GitDir() (string, error) {
	out, err := r.run(nil, "rev-parse", "--absolute-git-dir")
	return strings.TrimSpace(out), err
}

// CurrentBranch returns the full ref HEAD points to (e.g. refs/heads/main).
func (r *Repo) CurrentBranch() (string, error) {
	out, err := r.run(nil, "symbolic-ref", "HEAD")
	return strings.TrimSpace(out), err
}

// Change is one entry of a tree diff.
type Change struct {
	Status byte // A, M, D (renames/copies are reported as D+A)
	Path   string
}

// ChangedFiles lists files that differ between two commits. An empty old
// means "empty tree" (first push).
func (r *Repo) ChangedFiles(old, new string) ([]Change, error) {
	if old == "" {
		old = "4b825dc642cb6eb9a060e54bf8d69288fbee4904" // empty tree
	}
	out, err := r.run(nil, "diff", "--no-renames", "--name-status", "-z", old, new)
	if err != nil {
		return nil, err
	}
	f := strings.Split(strings.TrimSuffix(out, "\x00"), "\x00")
	var cs []Change
	for i := 0; i+1 < len(f); i += 2 {
		if f[i] != "" {
			cs = append(cs, Change{Status: f[i][0], Path: f[i+1]})
		}
	}
	return cs, nil
}

// Show returns a file's content at a revision.
func (r *Repo) Show(rev, path string) ([]byte, error) {
	out, err := r.run(nil, "show", rev+":"+path)
	return []byte(out), err
}

// Unstage removes paths from the index (best effort, used after a failed commit).
func (r *Repo) Unstage(paths []string) {
	r.run(nil, append([]string{"reset", "-q", "--"}, paths...)...)
}

// Head returns the current commit hash, or "" if there are no commits yet.
func (r *Repo) Head() (string, error) {
	out, err := r.run(nil, "rev-parse", "-q", "--verify", "HEAD")
	if err != nil {
		if _, err2 := r.run(nil, "rev-parse", "--git-dir"); err2 == nil {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(out), nil
}
