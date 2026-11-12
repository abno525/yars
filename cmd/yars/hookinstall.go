package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"yars/internal/db"
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
	dir := *data
	if dir == "" {
		dir = "."
	}
	targets, err := hookTargets(dir)
	if err != nil {
		return err
	}
	bin, err := hookBin()
	if err != nil {
		return err
	}
	if abs, err := filepath.Abs(bin); err == nil {
		bin = abs
	}
	line := shellQuote(bin) + " lint --staged --warn-only"
	n := 0
	for _, t := range targets {
		path, err := hookPath(t.dir)
		if err != nil {
			return err
		}
		ok, err := writeHook(path, bin)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintf(out, "%s: a pre-commit hook exists already; add this line to it: %s\n", path, line)
			continue
		}
		fmt.Fprintf(out, "installed %s\n", t.id)
		n++
	}
	fmt.Fprintf(out, "%d installed\n", n)
	return nil
}

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

// writeHook writes our hook to path; false when a hook someone else wrote
// is there (it is left alone).
func writeHook(path, bin string) (bool, error) {
	if b, err := os.ReadFile(path); err == nil && !strings.Contains(string(b), hookMarker) {
		return false, nil
	} else if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	q := shellQuote(bin)
	body := "#!/bin/sh\n" + hookMarker + "\ntest -x " + q + " || exit 0\nexec " + q + " lint --staged --warn-only\n"
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
