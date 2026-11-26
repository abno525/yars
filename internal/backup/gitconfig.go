package backup

import (
	"errors"
	"slices"
	"strings"
)

// A backup's git folders come from a ZIP anyone with the admin flag can
// upload, and git runs programs its folder names: hooks, and config keys
// such as core.fsmonitor, core.hooksPath, include.path and filter drivers.
// A restore therefore takes no hook and none of those files, and writes each
// config again from the settings below. The server's own settings and its
// push hook come back at its next start (gitserve's setup).

// gitConfigValues are the config settings a restore keeps, each with the
// values it may have: what makes the repository readable as it was written.
var gitConfigValues = map[string][]string{
	"core.repositoryformatversion": {"0", "1"},
	"core.filemode":                {"true", "false"},
	"core.bare":                    {"true", "false"},
	"core.logallrefupdates":        {"true", "false", "always"},
	"extensions.objectformat":      {"sha1", "sha256"},
	"extensions.refstorage":        {"files", "reftable"},
}

// gitConfigOrder is the order the kept settings are written in.
var gitConfigOrder = []string{"core.repositoryformatversion", "core.filemode", "core.bare", "core.logallrefupdates", "extensions.objectformat", "extensions.refstorage"}

// gitConfigKeys are the names of the kept settings.
var gitConfigKeys = func() map[string]bool {
	m := map[string]bool{}
	for k := range gitConfigValues {
		m[k] = true
	}
	return m
}()

// cleanGitConfig returns a git config that holds only the kept settings of
// b, read from plain "key = value" lines under a plain [section] line. Any
// other line, section or value is left out; git never reads b itself.
func cleanGitConfig(b []byte) []byte {
	got := map[string]string{}
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			section = ""
			if name, ok := strings.CutSuffix(line[1:], "]"); ok {
				section = strings.ToLower(name)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || section == "" {
			continue
		}
		key := section + "." + strings.ToLower(strings.TrimSpace(k))
		if v = strings.ToLower(strings.TrimSpace(v)); slices.Contains(gitConfigValues[key], v) {
			got[key] = v
		}
	}
	if _, ok := got["core.repositoryformatversion"]; !ok {
		got["core.repositoryformatversion"] = "0"
	}
	// an extension is read only at version 1
	if got["extensions.objectformat"] != "" || got["extensions.refstorage"] != "" {
		got["core.repositoryformatversion"] = "1"
	}
	var out strings.Builder
	section = ""
	for _, key := range gitConfigOrder {
		v, ok := got[key]
		if !ok {
			continue
		}
		sec, name, _ := strings.Cut(key, ".")
		if sec != section {
			section = sec
			out.WriteString("[" + sec + "]\n")
		}
		out.WriteString("\t" + name + " = " + v + "\n")
	}
	return []byte(out.String())
}

// gitPart returns the path of name inside a git folder (segments after a
// ".git" one) and whether name is in one; the ".git" entry itself has none.
func gitPart(name string) ([]string, bool) {
	segs := strings.Split(strings.TrimSuffix(name, "/"), "/")
	i := slices.Index(segs, ".git")
	if i < 0 {
		return nil, false
	}
	return segs[i+1:], true
}

// gitLayout notes where a ZIP's entries would make git find a repository.
// The clean-up of a restore covers what is under a .git folder, so that
// must be the only place git finds one. When a .git folder is no
// repository, git takes the folder it runs in as the git folder if that
// holds HEAD, objects and refs, with the config and the hooks beside them,
// and looks in the folders above otherwise.
type gitLayout struct {
	dotGit map[string]bool            // .git folders, by path
	head   map[string]bool            // those that hold a file HEAD
	bare   map[string]map[string]bool // outside .git: folder -> which of HEAD, objects, refs it holds
}

// note records the ZIP entry name (dir: a folder).
func (l *gitLayout) note(name string, dir bool) {
	if l.dotGit == nil {
		l.dotGit, l.head, l.bare = map[string]bool{}, map[string]bool{}, map[string]map[string]bool{}
	}
	segs := strings.Split(strings.TrimSuffix(name, "/"), "/")
	if i := slices.Index(segs, ".git"); i >= 0 {
		p := strings.Join(segs[:i+1], "/")
		l.dotGit[p] = true
		if len(segs) == i+2 && segs[i+1] == "HEAD" && !dir {
			l.head[p] = true
		}
		return
	}
	for i, seg := range segs {
		if seg != "HEAD" && seg != "objects" && seg != "refs" {
			continue
		}
		d := strings.Join(segs[:i], "/")
		if l.bare[d] == nil {
			l.bare[d] = map[string]bool{}
		}
		l.bare[d][seg] = true
	}
}

// refuse is why the ZIP is not restored: a .git folder without HEAD, or a
// folder outside .git that git would take as a git folder. The first by
// name, so the message is the same each time.
func (l *gitLayout) refuse() error {
	var bad []string
	for p := range l.dotGit {
		if !l.head[p] {
			bad = append(bad, p+": holds no HEAD; it is not a repository")
		}
	}
	for d, has := range l.bare {
		if len(has) == 3 {
			if d == "" {
				d = "the data folder"
			}
			bad = append(bad, d+": a git folder outside .git")
		}
	}
	if len(bad) == 0 {
		return nil
	}
	slices.Sort(bad)
	return errors.New(bad[0])
}

// gitDropped reports whether a restore leaves the git-folder file with the
// inner path part out: hooks, and what makes git read settings or a git
// folder from elsewhere.
func gitDropped(part []string) bool {
	if len(part) == 0 {
		return false
	}
	switch part[0] {
	case "hooks", "worktrees", "modules":
		return true
	}
	switch strings.Join(part, "/") {
	case "config.worktree", "commondir", "info/attributes":
		return true
	}
	return false
}
