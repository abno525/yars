package gitrepo

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// The oldest git YARS works with: rev-parse knows --end-of-options from
// 2.30 on (Repo.Ref passes it; on an older git Ref reads every ref as
// missing, and every push is refused as behind the server), and init knows
// -b from 2.28 on.
const (
	MinMajor = 2
	MinMinor = 30
)

// MinVersion is the oldest git YARS works with, as the docs name it.
func MinVersion() string { return strconv.Itoa(MinMajor) + "." + strconv.Itoa(MinMinor) }

// ErrNoGit: there is no git to run.
var ErrNoGit = errors.New("git is not on the PATH")

// ErrVersionUnread: what git version printed is no version this code reads.
// It is no proof of an old git: a caller goes on and says so.
var ErrVersionUnread = errors.New("the git version does not read")

// VersionText is what `git version` prints (ErrNoGit without a git).
func VersionText() (string, error) {
	out, err := within(Timeout, nil, nil, []string{"version"}, []string{"version"})
	if errors.Is(err, exec.ErrNotFound) {
		return "", ErrNoGit
	}
	return string(out), err
}

// ParseVersion reads the first two numbers of a git version: of `git
// version 2.43.0`, or of the version alone. What follows them varies
// (`2.39.3 (Apple Git-146)`, `2.30.0.windows.1`, `2.45.GIT`, `2.44.0-rc1`)
// and is not read.
func ParseVersion(text string) (major, minor int, ok bool) {
	rest := strings.TrimPrefix(strings.TrimSpace(text), "git version ")
	major, rest, ok = leadingNumber(rest)
	if !ok || !strings.HasPrefix(rest, ".") {
		return 0, 0, false
	}
	minor, _, ok = leadingNumber(rest[1:])
	if !ok {
		return 0, 0, false
	}
	return major, minor, true
}

// leadingNumber reads the decimal digits s starts with (one to six of
// them: no version number is longer, and it cannot overflow) and returns
// what follows.
func leadingNumber(s string) (n int, rest string, ok bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || i > 6 {
		return 0, s, false
	}
	n, err := strconv.Atoi(s[:i])
	return n, s[i:], err == nil
}

// CheckVersionText judges what `git version` printed: the version as
// major.minor and nil when it is MinVersion or later, an error that names
// both versions when it is older, and ErrVersionUnread when text is no
// version. The numbers are compared as numbers (2.9 is older than 2.30).
//
// Neither error holds text itself: it is another program's output. The old
// git's error names the two numbers that were read.
func CheckVersionText(text string) (string, error) {
	major, minor, ok := ParseVersion(text)
	if !ok {
		return "", ErrVersionUnread
	}
	version := strconv.Itoa(major) + "." + strconv.Itoa(minor)
	if major < MinMajor || major == MinMajor && minor < MinMinor {
		return version, fmt.Errorf("git %s or later is needed; this is git %s", MinVersion(), version)
	}
	return version, nil
}
