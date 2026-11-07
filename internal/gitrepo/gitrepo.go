// Package gitrepo is a thin wrapper around the git CLI.
package gitrepo

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
	cmd := exec.Command("git", append([]string{"-C", r.Dir, "-c", "commit.gpgsign=false", "-c", "advice.addEmbeddedRepo=false"}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	spawned.Add(1)
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
		spawned.Add(1)
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

// Gitlink returns the commit a submodule path points to at rev ("" when the
// path is not a gitlink there).
func (r *Repo) Gitlink(rev, p string) (string, error) {
	out, err := r.run(nil, "ls-tree", rev, "--", p)
	if err != nil {
		return "", err
	}
	f := strings.Fields(out)
	if len(f) >= 3 && f[0] == "160000" && f[1] == "commit" {
		return f[2], nil
	}
	return "", nil
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
	Status byte   // A, M, D, T (renames/copies are reported as D+A)
	Path   string //
	Mode   string // new file mode (e.g. 100644, 120000 for symlinks); 000000 when deleted
}

// ChangedFiles lists files that differ between two commits. An empty old
// means "empty tree" (first push).
func (r *Repo) ChangedFiles(old, new string) ([]Change, error) {
	if old == "" {
		old = "4b825dc642cb6eb9a060e54bf8d69288fbee4904" // empty tree
	}
	// --ignore-submodules=none: .gitmodules says ignore = all for every
	// engagement, which would hide a moved or removed pointer
	out, err := r.run(nil, "diff", "--no-renames", "--ignore-submodules=none", "--raw", "-z", old, new)
	if err != nil {
		return nil, err
	}
	f := strings.Split(strings.TrimSuffix(out, "\x00"), "\x00")
	var cs []Change
	for i := 0; i+1 < len(f); i += 2 {
		meta := strings.Fields(strings.TrimPrefix(f[i], ":"))
		if len(meta) < 5 {
			continue
		}
		cs = append(cs, Change{Status: meta[4][0], Path: f[i+1], Mode: meta[1]})
	}
	return cs, nil
}

// CommitAuthor identifies who a commit claims to be authored by.
type CommitAuthor struct{ Hash, Name, Email string }

// Authors lists the authors of commits in old..new (all of new when old is "").
func (r *Repo) Authors(old, new string) ([]CommitAuthor, error) {
	rng := new
	if old != "" {
		rng = old + ".." + new
	}
	out, err := r.run(nil, "log", "--format=%H%x00%an%x00%ae", rng)
	if err != nil {
		return nil, err
	}
	var as []CommitAuthor
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if p := strings.Split(line, "\x00"); len(p) == 3 {
			as = append(as, CommitAuthor{p[0], p[1], p[2]})
		}
	}
	return as, nil
}

// Tracked reports whether path is in the index.
func (r *Repo) Tracked(path string) bool {
	out, err := r.run(nil, "ls-files", "--", path)
	return err == nil && strings.TrimSpace(out) != ""
}

// Untrack removes path from the index (keeping the file) and commits.
func (r *Repo) Untrack(path, msg string, a Author) error {
	if _, err := r.run(nil, "rm", "-q", "--cached", "--", path); err != nil {
		return err
	}
	env := []string{"GIT_AUTHOR_NAME=" + a.Name, "GIT_AUTHOR_EMAIL=" + a.Email, "GIT_COMMITTER_NAME=" + a.Name, "GIT_COMMITTER_EMAIL=" + a.Email}
	// commit just the staged removal (a pathspec would re-read the file from disk)
	_, err := r.run(env, "commit", "-q", "-m", msg)
	return err
}

// ListTree returns the entry names directly under dir at rev.
func (r *Repo) ListTree(rev, dir string) ([]string, error) {
	out, err := r.run(nil, "ls-tree", "--name-only", "-z", rev, strings.TrimSuffix(dir, "/")+"/")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, p := range strings.Split(strings.TrimSuffix(out, "\x00"), "\x00") {
		if p != "" {
			names = append(names, path.Base(p))
		}
	}
	return names, nil
}

// Show returns a file's content at a revision.
func (r *Repo) Show(rev, path string) ([]byte, error) {
	out, err := r.run(nil, "cat-file", "blob", rev+":"+path)
	return []byte(out), err
}

// LogEntry is one commit that touched a file, with the file's path in it
// (Paths: every file it touched under the logged path).
type LogEntry struct {
	Hash, Author, Subject, Path string
	Paths                       []string
	Time                        time.Time
}

// LogFollow lists the commits touching p (following renames), newest
// first: one git process.
func (r *Repo) LogFollow(p string) ([]LogEntry, error) {
	out, err := r.run(nil, "-c", "core.quotePath=false", "log", "--follow", "--name-only", "--format=%x1e%H%x1f%an%x1f%at%x1f%s", "--", p)
	if err != nil {
		return nil, err
	}
	return parseLog(out), nil
}

// LogDir lists the commits touching files under dir, newest first, each
// with the files it touched there: one git process.
func (r *Repo) LogDir(dir string) ([]LogEntry, error) {
	out, err := r.run(nil, "-c", "core.quotePath=false", "log", "--name-only", "--format=%x1e%H%x1f%an%x1f%at%x1f%s", "--", dir)
	if err != nil {
		return nil, err
	}
	return parseLog(out), nil
}

func parseLog(out string) []LogEntry {
	var es []LogEntry
	for _, chunk := range strings.Split(out, "\x1e") {
		head, rest, _ := strings.Cut(chunk, "\n")
		f := strings.Split(head, "\x1f")
		if len(f) != 4 {
			continue
		}
		e := LogEntry{Hash: f[0], Author: f[1], Subject: f[3]}
		if sec, err := strconv.ParseInt(f[2], 10, 64); err == nil {
			e.Time = time.Unix(sec, 0)
		}
		for _, l := range strings.Split(rest, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				if e.Path == "" {
					e.Path = l
				}
				e.Paths = append(e.Paths, l)
			}
		}
		es = append(es, e)
	}
	return es
}

// Blobs reads files at revisions ("<rev>:<path>" each) in one git process;
// a missing one is nil.
func (r *Repo) Blobs(specs []string) ([][]byte, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	cmd := exec.Command("git", "-C", r.Dir, "cat-file", "--batch")
	cmd.Stdin = strings.NewReader(strings.Join(specs, "\n") + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	spawned.Add(1)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git cat-file: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	out := stdout.Bytes()
	res := make([][]byte, 0, len(specs))
	for range specs {
		nl := bytes.IndexByte(out, '\n')
		if nl < 0 {
			return nil, fmt.Errorf("git cat-file: short output")
		}
		hdr := strings.Fields(string(out[:nl]))
		out = out[nl+1:]
		if len(hdr) != 3 {
			res = append(res, nil) // "<spec> missing"
			continue
		}
		n, err := strconv.Atoi(hdr[2])
		if err != nil || n+1 > len(out) {
			return nil, fmt.Errorf("git cat-file: bad header %q", hdr)
		}
		res = append(res, bytes.Clone(out[:n]))
		out = out[n+1:]
	}
	return res, nil
}

// Unstage removes paths from the index (best effort, used after a failed commit).
func (r *Repo) Unstage(paths []string) {
	r.run(nil, append([]string{"reset", "-q", "--"}, paths...)...)
}

// Ref returns the commit a ref points to ("" when it does not exist).
func (r *Repo) Ref(ref string) string {
	out, err := r.run(nil, "rev-parse", "-q", "--verify", "--end-of-options", ref)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// RestoreHead puts the index and work tree back to HEAD when they differ
// from it (tracked files only), e.g. after a push checked its tree out but
// then failed to move the branch. It reports whether anything was reset.
func (r *Repo) RestoreHead() (bool, error) {
	out, err := r.run(nil, "status", "--porcelain", "--untracked-files=no", "--ignore-submodules=all")
	if err != nil || strings.TrimSpace(out) == "" {
		return false, err
	}
	if _, err := r.run(nil, "reset", "-q", "--hard", "HEAD"); err != nil {
		return false, err
	}
	return true, nil
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
