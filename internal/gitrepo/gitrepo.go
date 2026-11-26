// Package gitrepo is a thin wrapper around the git CLI.
package gitrepo

import (
	"bytes"
	"context"
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

// Timeout bounds every git command run through Repo.run (not the long-lived
// cat-file --batch processes, not git http-backend).
var Timeout = 2 * time.Minute

// waitDelay is how long a timed-out git's output is still read: a process it
// started (a hook) may hold the pipes open after git is killed.
const waitDelay = time.Second

// FsckTimeout bounds Fsck, which reads every object of the repository.
var FsckTimeout = time.Hour

func (r *Repo) run(env []string, args ...string) (string, error) {
	return r.runWithin(Timeout, env, args...)
}

// runWithin is run with its own time limit.
func (r *Repo) runWithin(timeout time.Duration, env []string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", r.Dir, "-c", "commit.gpgsign=false", "-c", "advice.addEmbeddedRepo=false"}, args...)...)
	cmd.WaitDelay = waitDelay
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	spawned.Add(1)
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("git %s: timed out after %s", shown(args), timeout)
		}
		msg := strings.TrimSpace(stderr.String())
		if msg == "" { // some commands say what is wrong on stdout (fsck)
			msg, _, _ = strings.Cut(strings.TrimSpace(stdout.String()), "\n")
		}
		return "", fmt.Errorf("git %s: %w: %s", shown(args), err, msg)
	}
	return stdout.String(), nil
}

// shown is a command line as an error names it: without -m and the commit
// message after it. The message holds what a person typed (an attachment's
// name, a section, a template), and the error is logged.
func shown(args []string) string {
	kept := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "-m" {
			i++
			continue
		}
		kept = append(kept, args[i])
	}
	return strings.Join(kept, " ")
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
	if err := os.MkdirAll(dir, 0o700); err != nil {
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
// A file (or nested repository) named here is added even when a .gitignore
// matches it (a director may push any); a plain directory is added as git
// does, without the files it ignores.
func (r *Repo) Commit(paths []string, msg string, a Author) error {
	var named, dirs []string
	for _, p := range paths {
		full := filepath.Join(r.Dir, p)
		if fi, err := os.Stat(full); err == nil && fi.IsDir() {
			if _, err := os.Stat(filepath.Join(full, ".git")); err != nil {
				dirs = append(dirs, p)
				continue
			}
		}
		named = append(named, p)
	}
	if len(named) > 0 {
		if _, err := r.run(nil, append([]string{"add", "-A", "-f", "--"}, named...)...); err != nil {
			return err
		}
	}
	if len(dirs) > 0 {
		if _, err := r.run(nil, append([]string{"add", "-A", "--"}, dirs...)...); err != nil {
			return err
		}
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

// Fsck checks the repository's objects and refs (git fsck --no-dangling),
// within FsckTimeout.
func (r *Repo) Fsck() error {
	_, err := r.runWithin(FsckTimeout, nil, "fsck", "--no-dangling")
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
	Status byte   // A, M, D, T (renames/copies are reported as D+A)
	Path   string //
	Mode   string // new file mode (e.g. 100644, 120000 for symlinks); 000000 when deleted
	Blob   string // the new content's object id (zeros when deleted)
}

// ChangedFiles lists files that differ between two commits. An empty old
// means "empty tree" (first push).
func (r *Repo) ChangedFiles(old, new string) ([]Change, error) {
	if old == "" {
		var err error
		if old, err = r.emptyTree(); err != nil {
			return nil, err
		}
	}
	// --ignore-submodules=none: .gitmodules says ignore = all for every
	// engagement, which would hide a moved or removed pointer; --no-abbrev:
	// full blob ids (a purged blob is matched by its id, D28)
	out, err := r.run(nil, "diff", "--no-renames", "--no-abbrev", "--ignore-submodules=none", "--raw", "-z", old, new)
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
		cs = append(cs, Change{Status: meta[4][0], Path: f[i+1], Mode: meta[1], Blob: meta[3]})
	}
	return cs, nil
}

// emptyTree is the empty tree's id in r's object format (SHA-256 only in
// a repository made with it by hand).
func (r *Repo) emptyTree() (string, error) {
	out, err := r.run(nil, "rev-parse", "--show-object-format")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(out) == "sha256" {
		return "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321", nil
	}
	return "4b825dc642cb6eb9a060e54bf8d69288fbee4904", nil
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

// PushedCommit is one commit of a push: its hash, parents and author.
type PushedCommit struct {
	Hash    string
	Parents []string
	Author  CommitAuthor
}

// Commits lists the commits in old..new (all of new when old is ""),
// parents before children.
func (r *Repo) Commits(old, new string) ([]PushedCommit, error) {
	rng := new
	if old != "" {
		rng = old + ".." + new
	}
	out, err := r.run(nil, "log", "--reverse", "--topo-order", "--format=%H%x00%P%x00%an%x00%ae", rng)
	if err != nil {
		return nil, err
	}
	var cs []PushedCommit
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		p := strings.Split(line, "\x00")
		if len(p) != 4 {
			continue
		}
		cs = append(cs, PushedCommit{Hash: p[0], Parents: strings.Fields(p[1]), Author: CommitAuthor{p[0], p[2], p[3]}})
	}
	return cs, nil
}

// Sizes returns the size in bytes of objects (ids, never paths) without
// reading them, in one git process; a missing one is -1.
func (r *Repo) Sizes(specs []string) ([]int64, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	cmd := exec.Command("git", "-C", r.Dir, "cat-file", "--batch-check=%(objectsize)")
	cmd.Stdin = strings.NewReader(strings.Join(specs, "\n") + "\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	spawned.Add(1)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git cat-file: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(lines) != len(specs) {
		return nil, fmt.Errorf("git cat-file: %d sizes for %d files", len(lines), len(specs))
	}
	out := make([]int64, len(specs))
	for i, l := range lines {
		n, err := strconv.ParseInt(strings.TrimSpace(l), 10, 64)
		if err != nil {
			n = -1 // "<spec> missing"
		}
		out[i] = n
	}
	return out, nil
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
