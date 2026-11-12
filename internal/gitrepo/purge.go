package gitrepo

import (
	"fmt"
	"strings"
)

// D28: an attachment's earlier versions can be removed from history.

// BlobsOf lists the distinct blob ids path has had in the history of HEAD,
// newest first.
func (r *Repo) BlobsOf(path string) ([]string, error) {
	out, err := r.run(nil, "log", "--raw", "--no-abbrev", "--no-renames", "--format=", "HEAD", "--", path)
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

// ResetTo moves the current branch, index and work tree back to commit (a
// purge that failed half-way: the old commits are still there until gc).
func (r *Repo) ResetTo(commit string) error {
	_, err := r.run(nil, "reset", "-q", "--hard", commit)
	return err
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
// rewrite and before the objects are removed (a failure there leaves the
// old commits in the repository, reachable again by a reset).
func (r *Repo) DropOldBlobsWith(path, keep string, beforeGC func() error) error {
	branch, err := r.CurrentBranch()
	if err != nil {
		return err
	}
	env := []string{"FILTER_BRANCH_SQUELCH_WARNING=1", "YARS_P=" + path, "YARS_KEEP=" + keep}
	if _, err := r.runWithin(FsckTimeout, env, "filter-branch", "-f", "--index-filter", purgeFilter, "--", "HEAD"); err != nil {
		return err
	}
	if _, err := r.run(nil, "update-ref", "-d", "refs/original/"+branch); err != nil {
		return err
	}
	if _, err := r.run(nil, "reflog", "expire", "--expire=now", "--all"); err != nil {
		return err
	}
	if beforeGC != nil {
		if err := beforeGC(); err != nil {
			return fmt.Errorf("before gc: %w", err)
		}
	}
	_, err = r.runWithin(FsckTimeout, nil, "gc", "--prune=now", "--quiet")
	return err
}
