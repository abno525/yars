package docs

import (
	"strings"
	"testing"
)

// The git guide says what a pull with submodules does to the engagement
// repositories and how to put them back on main (backlog, M11).
func TestGitGuidePullSubmodules(t *testing.T) {
	g, err := Page("git")
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(g, "## Cloning and pulling")
	if i < 0 {
		t.Fatal("no Cloning and pulling section")
	}
	sec := g[i:]
	if j := strings.Index(sec[3:], "\n## "); j >= 0 {
		sec = sec[:j+3]
	}
	for _, want := range []string{"git clone --recurse-submodules", "git pull --recurse-submodules", "detached HEAD", "git submodule foreach git switch -q main"} {
		if !strings.Contains(sec, want) {
			t.Errorf("the section lacks %q", want)
		}
	}
}
