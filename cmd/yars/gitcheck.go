package main

import (
	"errors"
	"log/slog"

	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/logs"
)

// gitVersionText is what `git version` prints on this machine (a test
// gives its own text).
var gitVersionText = gitrepo.VersionText

// checkGit judges the machine's git before a command changes anything: a
// missing git and one older than gitrepo.MinVersion are errors (an old git
// does not fail at the start but in the middle of the work: every push is
// refused as behind the server). A version that does not read is no proof
// of an old git, so it stops nothing: unread is true, and the caller says
// so (logGitUnread).
func checkGit() (unread bool, err error) {
	text, err := gitVersionText()
	if err != nil {
		return false, err
	}
	_, err = gitrepo.CheckVersionText(text)
	if errors.Is(err, gitrepo.ErrVersionUnread) {
		return true, nil
	}
	return false, err
}

// logGitUnread writes the one line of a start whose git's version did not
// read. It never holds what git printed.
func logGitUnread(lg *slog.Logger) {
	logs.Or(lg).Warn("git: the version does not read; the start goes on (YARS needs git 2.30 or later)")
}
