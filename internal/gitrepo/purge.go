package gitrepo

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// D28: an attachment's earlier versions can be removed from history.

// literal makes git read a path as itself, never as a pattern.
var literal = []string{"GIT_LITERAL_PATHSPECS=1"}

// BlobsOf lists the distinct blob ids path has had in the history of HEAD,
// newest first: every commit (no history simplification), and a merge's
// own version against each of its parents.
func (r *Repo) BlobsOf(path string) ([]string, error) {
	return r.BlobsWhere(func(p string) bool { return p == path })
}

// BlobsWhere is BlobsOf for every path match accepts (the names a file had
// before a push renamed it or its folder; git's own rename detection would
// also take a different, similar file for one).
func (r *Repo) BlobsWhere(match func(path string) bool) ([]string, error) {
	var blobs []string
	seen := map[string]bool{}
	err := r.eachChange(func(blob, path string) {
		if match(path) && !seen[blob] {
			seen[blob] = true
			blobs = append(blobs, blob)
		}
	})
	return blobs, err
}

// pathsOf lists every path at which one of blobs appears in the history of
// HEAD (a copy, a file or folder renamed since).
func (r *Repo) pathsOf(blobs map[string]bool) ([]string, error) {
	var paths []string
	seen := map[string]bool{}
	err := r.eachChange(func(blob, path string) {
		if blobs[blob] && !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	})
	return paths, err
}

// eachChange calls fn, newest first, for every file version a commit of
// HEAD's history wrote (no history simplification; a merge against each of
// its parents; the first commit too, whatever log.showRoot says: a
// retest's copies are in it; deletions left out).
func (r *Repo) eachChange(fn func(blob, path string)) error {
	out, err := r.run(nil, "log", "--raw", "--root", "-z", "--no-abbrev", "--no-renames", "--full-history", "-m", "--format=", "HEAD")
	if err != nil {
		return err
	}
	meta := ""
	// NUL-separated: a meta field (":<mode> <mode> <old> <new> <status>",
	// after a commit's line breaks), then its path, taken as it is
	for _, tok := range strings.Split(out, "\x00") {
		if meta == "" {
			if m := strings.TrimLeft(tok, "\n"); strings.HasPrefix(m, ":") {
				meta = m
			}
			continue
		}
		if f := strings.Fields(meta); len(f) >= 5 && strings.Trim(f[3], "0") != "" {
			fn(f[3], tok)
		}
		meta = ""
	}
	return nil
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

// treeEntry is one file of a tree.
type treeEntry struct{ ID, Path string }

func (r *Repo) treeFiles(rev string) ([]treeEntry, error) {
	out, err := r.run(nil, "ls-tree", "-r", "-z", "--full-tree", rev)
	if err != nil {
		return nil, err
	}
	var es []treeEntry
	for _, e := range strings.Split(out, "\x00") {
		// <mode> blob <id><TAB>path
		head, p, _ := strings.Cut(e, "\t")
		if f := strings.Fields(head); len(f) == 3 && f[1] == "blob" {
			es = append(es, treeEntry{f[2], p})
		}
	}
	return es, nil
}

// TreeBlobs is the set of blob ids in rev's tree.
func (r *Repo) TreeBlobs(rev string) (map[string]bool, error) {
	es, err := r.treeFiles(rev)
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, e := range es {
		ids[e.ID] = true
	}
	return ids, nil
}

// GC removes the objects nothing reaches any more.
func (r *Repo) GC() error {
	_, err := r.runWithin(FsckTimeout, nil, "gc", "--prune=now", "--quiet")
	return err
}

// ResetTo moves the current branch, index and work tree back to commit (a
// purge that failed half-way: the old commits are still there until gc).
func (r *Repo) ResetTo(commit string) error {
	_, err := r.run(nil, "reset", "-q", "--hard", commit)
	return err
}

// ErrPurgeCleanup: a drop's gc failed. The history is rewritten and the
// old objects may still be on disk; there is no way back, and GC finishes
// the job.
var ErrPurgeCleanup = errors.New("purged; cleanup failed")

// ElsewhereError: an earlier version of Path is also At another path of the
// current files (the same bytes under another name), so it would stay.
type ElsewhereError struct{ Path, At string }

func (e *ElsewhereError) Error() string {
	return fmt.Sprintf("an earlier version of %s is also at %s; redact it there first", e.Path, e.At)
}

// purgeFilter is filter-branch's index filter: every listed path whose
// content is one of the listed blobs leaves the commit.
const purgeFilter = `while IFS= read -r p; do b=$(git rev-parse -q --verify ":$p") && grep -qxF -e "$b" "$YARS_IDS" && git rm -q --cached --ignore-unmatch -- "$p"; done < "$YARS_PATHS"; true`

// DropOldBlobs rewrites every commit of the current branch so that no
// version path had but keep is left in it, at that path or any other (a
// copy, a folder renamed since), then removes the unreachable objects. The
// work tree is not changed.
func (r *Repo) DropOldBlobs(path, keep string) error {
	return r.DropOldBlobsWith(path, keep, nil, nil)
}

// DropOldBlobsWith is DropOldBlobs for the versions oldIDs (nil: the ones
// BlobsOf(path) lists, but keep), wherever they are; beforeGC, when set,
// runs after the rewrite and before the objects are removed. An old
// version still in the current files under another name is an
// ElsewhereError, before anything changes. Until gc runs, a failure leaves
// the old commits in the repository, reachable again by a reset: keep must
// be path's version at HEAD (HEAD's files may not change). A gc failure,
// or an old version still on disk after it, is ErrPurgeCleanup.
func (r *Repo) DropOldBlobsWith(path, keep string, oldIDs []string, beforeGC func() error) (err error) {
	branch, err := r.CurrentBranch()
	if err != nil {
		return err
	}
	all := oldIDs
	if all == nil {
		if all, err = r.BlobsOf(path); err != nil {
			return err
		}
	}
	old := map[string]bool{}
	var ids []string
	for _, b := range all {
		if b != keep && !old[b] {
			old[b] = true
			ids = append(ids, b)
		}
	}
	if len(old) == 0 {
		return nil
	}
	// the current files must not hold an old version under another name:
	// the rewrite would take it out of them
	head, err := r.treeFiles("HEAD")
	if err != nil {
		return err
	}
	for _, e := range head {
		if old[e.ID] && e.Path != path {
			return &ElsewhereError{Path: path, At: e.Path}
		}
	}
	paths, err := r.pathsOf(old)
	if err != nil {
		return err
	}
	var list strings.Builder
	for _, p := range paths {
		if !strings.ContainsAny(p, "\n\r") { // the safety check below catches the rest
			list.WriteString(p + "\n")
		}
	}
	gitDir, err := r.run(nil, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return err
	}
	gitDir = strings.TrimSpace(gitDir)
	idsFile, pathsFile := filepath.Join(gitDir, "yars-purge-ids"), filepath.Join(gitDir, "yars-purge-paths")
	if err := os.WriteFile(idsFile, []byte(strings.Join(ids, "\n")+"\n"), 0o600); err != nil {
		return err
	}
	defer os.Remove(idsFile)
	if err := os.WriteFile(pathsFile, []byte(list.String()), 0o600); err != nil {
		return err
	}
	defer os.Remove(pathsFile)
	tree0, err := r.run(nil, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return err
	}
	// filter-branch keeps the branch as it was under refs/original: gone
	// on success, and on any failure (the caller resets the branch)
	defer func() {
		if err != nil {
			r.run(nil, "update-ref", "-d", "refs/original/"+branch)
		}
	}()
	env := append([]string{"FILTER_BRANCH_SQUELCH_WARNING=1", "YARS_IDS=" + idsFile, "YARS_PATHS=" + pathsFile}, literal...)
	// its scratch folder in the git folder: one left by a stop is not in
	// the work tree, and -f clears it next time
	if _, err := r.runWithin(FsckTimeout, env, "filter-branch", "-f", "-d", filepath.Join(gitDir, "yars-rewrite"), "--index-filter", purgeFilter, "--", "HEAD"); err != nil {
		return err
	}
	if tree1, err := r.run(nil, "rev-parse", "HEAD^{tree}"); err != nil {
		return err
	} else if tree1 != tree0 {
		return fmt.Errorf("the purge would change the current files (%s is not %s at HEAD)", short(keep), path)
	}
	// a safety check before anything is expired: no ref but the backup
	// still reaches an old version (another ref, a path the list missed)
	objs, err := r.runWithin(FsckTimeout, nil, "rev-list", "--objects", "--exclude=refs/original/*", "--all")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(objs, "\n") {
		id, p, _ := strings.Cut(line, " ")
		if old[id] {
			// not the director's to fix (a path only history has): a server error
			return fmt.Errorf("an earlier version of %s is still reachable after the rewrite (%q)", path, p)
		}
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
	if err := r.GC(); err != nil {
		return fmt.Errorf("%w: %v", ErrPurgeCleanup, err)
	}
	return r.gone(ids)
}

// gone checks that none of ids is on disk any more.
func (r *Repo) gone(ids []string) error {
	sizes, err := r.Sizes(ids)
	if err != nil {
		return err
	}
	for i, n := range sizes {
		if n >= 0 {
			return fmt.Errorf("%w: %s is still on disk", ErrPurgeCleanup, short(ids[i]))
		}
	}
	return nil
}

// FinishDrop completes a drop that stopped after its rewrite (the server
// stopped, gc failed): the backup refs and the reflogs go, then gc runs
// while one of ids that no ref reaches is still on disk (one history holds
// again, uploaded once more, is not the drop's to remove). One that stays
// is ErrPurgeCleanup.
func (r *Repo) FinishDrop(ids []string) error {
	refs, err := r.run(nil, "for-each-ref", "--format=%(refname)", "refs/original/")
	if err != nil {
		return err
	}
	backup := strings.Fields(refs)
	for _, ref := range backup {
		if _, err := r.run(nil, "update-ref", "-d", ref); err != nil {
			return err
		}
	}
	objs, err := r.runWithin(FsckTimeout, nil, "rev-list", "--objects", "--all")
	if err != nil {
		return err
	}
	reached := map[string]bool{}
	for _, line := range strings.Split(objs, "\n") {
		id, _, _ := strings.Cut(line, " ")
		reached[id] = true
	}
	var want []string
	for _, id := range ids {
		if !reached[id] {
			want = append(want, id)
		}
	}
	sizes, err := r.Sizes(want)
	if err != nil {
		return err
	}
	left := false
	for _, n := range sizes {
		left = left || n >= 0
	}
	if !left && len(backup) == 0 {
		return nil
	}
	if _, err := r.run(nil, "reflog", "expire", "--expire=now", "--all"); err != nil {
		return err
	}
	if err := r.GC(); err != nil {
		return fmt.Errorf("%w: %v", ErrPurgeCleanup, err)
	}
	return r.gone(want)
}

func short(id string) string {
	if len(id) > 7 {
		return id[:7]
	}
	return id
}
