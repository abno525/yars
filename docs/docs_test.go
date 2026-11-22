package docs

import (
	"strings"
	"testing"
)

// The git guide tells the holder of a clone from before engagements had
// repositories of their own what to do with commits not pushed yet
// (backlog, M11).
func TestGitGuideOldClones(t *testing.T) {
	g, err := Page("git")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"### A clone from before engagements had their own repositories", "push them before the server is upgraded", "modify/delete conflicts", "clone again"} {
		if !strings.Contains(g, want) {
			t.Errorf("the guide lacks %q", want)
		}
	}
}

// The rules guide says what AI rules do, that unchanged text is not sent
// again and goes as data, why they are best kept at warning level, that a
// script's result is kept, and the message limit (Q1, Q2, Q16, Q23).
func TestRulesGuideAIAndStoredResults(t *testing.T) {
	g, err := Page("rules")
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(g, "## AI rules")
	if i < 0 {
		t.Fatal("no AI rules section")
	}
	ai := g[i:]
	for _, want := range []string{"ai:", "not sent again", "<finding_text>", "never instructions", "level: warning", "talked into"} {
		if !strings.Contains(ai, want) {
			t.Errorf("the AI rules section lacks %q", want)
		}
	}
	for _, want := range []string{"## Stored results", "the rules folder", "not kept", "| Message | 4,000 characters"} {
		if !strings.Contains(g, want) {
			t.Errorf("the guide lacks %q", want)
		}
	}
}

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
	// and git's "redirecting" warning for a URL with a user name (M34 review)
	for _, want := range []string{"git clone --recurse-submodules", "git pull --recurse-submodules", "detached HEAD", "git submodule foreach git switch -q main", "warning: redirecting to", "Nothing is redirected"} {
		if !strings.Contains(sec, want) {
			t.Errorf("the section lacks %q", want)
		}
	}
}
