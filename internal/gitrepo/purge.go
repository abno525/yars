package gitrepo

import (
	"errors"
	"fmt"
	"strings"
)

// D28: an attachment's earlier versions can be removed from history.

// literal makes git read a path as itself, never as a pattern.
var literal = []string{"GIT_LITERAL_PATHSPECS=1"}

// BlobsOf lists the distinct blob ids path has had in the history of HEAD,
// newest first: every commit (no history simplification), and a merge's
// own version against each of its parents.
func (r *Repo) BlobsOf(path string) ([]string, error) {
	out, err := r.run(literal, "log", "--raw", "--no-abbrev", "--no-renames", "--full-history", "-m", "--format=", "HEAD", "--", path)
	if err != nil {
		return nil, err
	}
	var blobs []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		// :100644 100644 <old> <new> M<TAB>path
		f := strings.Fields(line)
		if len(f) < 5 || !strings.HasPrefix(f[0], ":") {
			continue
		}
		b := f[3]
		if strings.Trim(b, "0") == "" || seen[b] {
			continue // deleted there
		}
		seen[b] = true
		blobs = append(blobs, b)
	}
	return blobs, nil
}

// BlobAt is the blob id of path at rev ("" when rev has no such file).
func (r *Repo) BlobAt(rev, path string) (string, error) {
	out, err := r.run(literal, "ls-tree", "--full-tree", rev, "--", path)
	if err != nil {
		return "", err
	}
	// <mode> blob <id><TAB>path
	if f := strings.Fields(out); len(f) >= 3 && f[1] == "blob" {
		return f[2], nil
	}
	return "", nil
}

// TreeBlobs is the set of blob ids in rev's tree.
func (r *Repo) TreeBlobs(rev string) (map[string]bool, error) {
	out, err := r.run(nil, "ls-tree", "-r", "-z", "--full-tree", rev)
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, e := range strings.Split(out, "\x00") {
		// <mode> blob <id><TAB>path
		if f := strings.Fields(strings.SplitN(e, "\t", 2)[0]); len(f) == 3 && f[1] == "blob" {
			ids[f[2]] = true
		}
	}
	return ids, nil
}

// ResetTo moves the current branch, index and work tree back to commit (a
// purge that failed half-way: the old commits are still there until gc).
func (r *Repo) ResetTo(commit string) error {
	_, err := r.run(nil, "reset", "-q", "--hard", commit)
	return err
}

// ErrPurgeCleanup: a drop's gc failed. The history is rewritten and the
// old objects may already be gone, so there is no way back.
var ErrPurgeCleanup = errors.New("purged; cleanup failed")

// ElsewhereError: an earlier version of Path is also at At (the same bytes
// under another name, or a folder renamed by a push), so it would stay.
type ElsewhereError struct{ Path, At string }

func (e *ElsewhereError) Error() string {
	return fmt.Sprintf("an earlier version of %s is also at %s; remove it there first", e.Path, e.At)
}

// purgeFilter is filter-branch's index filter: path stays only where its
// content is the blob to keep.
const purgeFilter = `test "$(git rev-parse -q --verify ":$YARS_P")" = "$YARS_KEEP" || git rm -q --cached --ignore-unmatch -- "$YARS_P"`

// DropOldBlobs rewrites every commit of the current branch so that path is
// absent wherever its content is not keep, then removes the unreachable
// objects. The work tree is not changed.
func (r *Repo) DropOldBlobs(path, keep string) error {
	return r.DropOldBlobsWith(path, keep, nil)
}

// DropOldBlobsWith is DropOldBlobs; beforeGC, when set, runs after the
// rewrite and before the objects are removed. Until gc runs, a failure
// leaves the old commits in the repository, reachable again by a reset:
// keep must be path's version at HEAD (HEAD's files may not change), and
// no other path may still hold an old version. A gc failure is
// ErrPurgeCleanup.
func (r *Repo) DropOldBlobsWith(path, keep string, beforeGC func() error) error {
	branch, err := r.CurrentBranch()
	if err != nil {
		return err
	}
	all, err := r.BlobsOf(path)
	if err != nil {
		return err
	}
	old := map[string]bool{}
	for _, b := range all {
		if b != keep {
			old[b] = true
		}
	}
	tree0, err := r.run(nil, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return err
	}
	env := append([]string{"FILTER_BRANCH_SQUELCH_WARNING=1", "YARS_P=" + path, "YARS_KEEP=" + keep}, literal...)
	if _, err := r.runWithin(FsckTimeout, env, "filter-branch", "-f", "--index-filter", purgeFilter, "--", "HEAD"); err != nil {
		return err
	}
	if tree1, err := r.run(nil, "rev-parse", "HEAD^{tree}"); err != nil {
		return err
	} else if tree1 != tree0 {
		return fmt.Errorf("the purge would change the current files (%s is not %s at HEAD)", short(keep), path)
	}
	if _, err := r.run(nil, "update-ref", "-d", "refs/original/"+branch); err != nil {
		return err
	}
	if _, err := r.run(nil, "reflog", "expire", "--expire=now", "--all"); err != nil {
		return err
	}
	// what gc would keep: the same bytes under another path (a copy, a
	// folder renamed by a push) are still history
	objs, err := r.runWithin(FsckTimeout, nil, "rev-list", "--objects", "--all")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(objs, "\n") {
		id, p, _ := strings.Cut(line, " ")
		if old[id] {
			return &ElsewhereError{Path: path, At: p}
		}
	}
	if beforeGC != nil {
		if err := beforeGC(); err != nil {
			return fmt.Errorf("before gc: %w", err)
		}
	}
	if _, err := r.runWithin(FsckTimeout, nil, "gc", "--prune=now", "--quiet"); err != nil {
		return fmt.Errorf("%w: %v", ErrPurgeCleanup, err)
	}
	return nil
}

func short(id string) string {
	if len(id) > 7 {
		return id[:7]
	}
	return id
}
