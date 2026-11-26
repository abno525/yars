package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/abno525/yars/internal/db"
)

// hookMarker is the line that tells our hook from someone else's.
const hookMarker = "# installed by yars hook install"

// hookBin is the binary the hook runs: the one running now (tests set it).
var hookBin = os.Executable

// hookTarget is one engagement repository of a clone.
type hookTarget struct{ id, dir string }

// cmdHookInstall writes the pre-commit hook into every engagement
// repository of the clone at --data (default: the current folder). The hook
// runs "yars lint --staged --warn-only": the server checks what is being
// committed, and the commit always goes in.
func cmdHookInstall(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("hook install", flag.ContinueOnError)
	data := fs.String("data", "", "the clone: a main clone or an engagement clone (default: the current folder)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: yars hook install [--data <clone>]")
	}
	dir := *data
	if dir == "" {
		dir = "."
	}
	targets, err := hookTargets(dir)
	if err != nil {
		return err
	}
	bin, err := hookBinPath()
	if err != nil {
		return err
	}
	line := shellQuote(bin) + " lint --staged --warn-only"
	n, failed := 0, 0
	for _, t := range targets {
		// core.hooksPath (a tracked folder of the work tree, or one shared by
		// every repository): nothing is written there; the user adds the line
		if hp, _ := exec.Command("git", "-C", t.dir, "config", "--get", "core.hooksPath").Output(); strings.TrimSpace(string(hp)) != "" {
			fmt.Fprintf(out, "%s: core.hooksPath is set (%s); add this line to its pre-commit hook: %s\n", t.dir, strings.TrimSpace(string(hp)), line)
			continue
		}
		path, err := hookPath(t.dir)
		var ok bool
		if err == nil {
			ok, err = writeHook(path, bin)
		}
		switch {
		case err != nil: // this engagement only: the others still get theirs
			fmt.Fprintf(out, "%s: %v\n", t.dir, err)
			failed++
		case !ok:
			fmt.Fprintf(out, "%s: a pre-commit hook exists already; add this line to it: %s\n", path, line)
		default:
			fmt.Fprintf(out, "installed %s\n", t.id)
			n++
		}
	}
	fmt.Fprintf(out, "%d installed\n", n)
	if failed > 0 {
		return fmt.Errorf("%d engagement(s) could not get the hook", failed)
	}
	return nil
}

// hookBinPath is the path the hook runs: the running binary, named as PATH
// finds it when that is the same file (a Homebrew or Nix link stays across
// upgrades; the resolved path os.Executable gives does not).
func hookBinPath() (string, error) {
	bin, err := hookBin()
	if err != nil {
		return "", err
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	if p, err := exec.LookPath("yars"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			a, errA := os.Stat(abs)
			b, errB := os.Stat(bin)
			if errA == nil && errB == nil && os.SameFile(a, b) {
				return abs, nil
			}
		}
	}
	return bin, nil
}

// hookBody is the hook for bin. It never stops a commit: a binary that is
// gone says so in one line, and one that fails (an older yars, a crash)
// still lets the commit go in.
func hookBody(bin string) string {
	q := shellQuote(bin)
	return "#!/bin/sh\n" + hookMarker + "\n" +
		"if ! test -x " + q + "; then\n" +
		"  echo \"yars: " + strings.ReplaceAll(q, `"`, `\"`) + " not found; this commit was not checked; run yars hook install again\" >&2\n" +
		"  exit 0\nfi\n" +
		q + " lint --staged --warn-only\nexit 0\n"
}

// ownHookRe matches hookBody for any binary path.
var ownHookRe = func() *regexp.Regexp {
	const ph = "\x00"
	quoted := regexp.QuoteMeta(shellQuote(ph))
	any := `'(?:[^']|'\\'')*'`
	pat := strings.ReplaceAll(regexp.QuoteMeta(hookBody(ph)), quoted, any)
	return regexp.MustCompile(`^` + pat + `$`)
}()

// ownHook reports whether b is a hook yars wrote, unchanged (lines the user
// added make it theirs).
func ownHook(b []byte) bool { return ownHookRe.Match(b) }

// hookTargets lists the engagement repositories of the clone at dir: every
// checked-out engagements/<id> of a main clone (it has .yars/config.yaml),
// or the engagement clone itself (it has engagement.yaml). The server's own
// data folder (it has the database) is refused: its commits are the server's.
func hookTargets(dir string) ([]hookTarget, error) {
	if exists(db.Path(dir)) {
		return nil, fmt.Errorf("%s is the server's data folder, not a clone; install the hook in a clone", dir)
	}
	switch {
	case exists(filepath.Join(dir, ".yars", "config.yaml")):
		ents, err := os.ReadDir(filepath.Join(dir, "engagements"))
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		var out []hookTarget
		for _, e := range ents {
			p := filepath.Join(dir, "engagements", e.Name())
			if e.IsDir() && exists(filepath.Join(p, ".git")) {
				out = append(out, hookTarget{e.Name(), p})
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
		return out, nil
	case exists(filepath.Join(dir, "engagement.yaml")):
		id := ""
		if origin, err := exec.Command("git", "-C", dir, "config", "--get", "remote.origin.url").Output(); err == nil {
			if u, ok := lintURL(strings.TrimSpace(string(origin))); ok {
				id = strings.TrimSuffix(u[strings.Index(u, "/git/e/")+len("/git/e/"):], "/lint")
			}
		}
		if id == "" {
			abs, err := filepath.Abs(dir)
			if err != nil {
				return nil, err
			}
			id = filepath.Base(abs)
		}
		return []hookTarget{{id, dir}}, nil
	}
	return nil, fmt.Errorf("%s is not a YARS clone", dir)
}

// hookPath is where git looks for the pre-commit hook of the repository at
// dir (a submodule's hooks live under the main clone's .git/modules).
func hookPath(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--git-path", "hooks/pre-commit").Output()
	if err != nil {
		return "", fmt.Errorf("%s: not a git repository: %w", dir, err)
	}
	p := strings.TrimSpace(string(out))
	if !filepath.IsAbs(p) {
		p = filepath.Join(dir, p)
	}
	return filepath.Abs(p)
}

// writeHook writes our hook to path; false when something else is there
// (left alone): a hook someone else wrote, ours with lines added, a symlink
// (even a dangling one) or a folder.
func writeHook(path, bin string) (bool, error) {
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() {
			return false, nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return false, err
		}
		if !ownHook(b) {
			return false, nil
		}
	} else if !os.IsNotExist(err) {
		return false, err
	}
	body := hookBody(bin)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	tmp := path + ".yars-tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o755); err != nil {
		return false, err
	}
	if err := os.Chmod(tmp, 0o755); err != nil { // the umask may have taken x away
		os.Remove(tmp)
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return false, err
	}
	return true, nil
}
