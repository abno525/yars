package docs

import (
	"io/fs"
	"os"
	"slices"
	"strings"
	"testing"
)

// The binary carries the pages of Pages and no other file of docs/: a
// planning note or an operator's page beside them is not compiled in.
func TestOnlyTheNamedPagesAreEmbedded(t *testing.T) {
	ents, err := fs.ReadDir(FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range ents {
		if e.IsDir() {
			t.Errorf("a folder is embedded: %s", e.Name())
		}
		got = append(got, e.Name())
	}
	var want []string
	for _, p := range Pages {
		want = append(want, p+".md")
		if s, err := Page(p); err != nil || s == "" {
			t.Errorf("Page(%q): %v", p, err)
		}
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("embedded %v, want %v", got, want)
	}
	for _, p := range []string{"open-decisions-2026-11-07", "deploy", "known-limits"} {
		if _, err := Page(p); err == nil {
			t.Errorf("%s.md is embedded", p)
		}
	}
}

// The limits page states limits: no planning file, milestone, decision
// number or commit of the project's history.
func TestKnownLimitsArePlain(t *testing.T) {
	b, err := os.ReadFile("known-limits.md")
	if err != nil {
		t.Fatal(err)
	}
	g := string(b)
	for _, bad := range []string{"superpowers", "M34", "M30", "M10", "M6", "Q25", "aca92e8", "Decided", "backlog", "chat.jsonl", "DeepSeek"} {
		if strings.Contains(g, bad) {
			t.Errorf("the limits page names %q", bad)
		}
	}
	for _, want := range []string{"## Checks and rules", "## Simple workflow", "AI rules skipped: no AI provider configured"} {
		if !strings.Contains(g, want) {
			t.Errorf("the limits page lacks %q", want)
		}
	}
}

// The rules guide covers every kind of rule: what the plain `yars lint`
// leaves out, the time one check has, how a pattern is anchored, who may
// dismiss, and each way a rule or its file can fail.
func TestRulesGuideCoversEveryKind(t *testing.T) {
	g, err := Page("rules")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(g, "# Rules\n") {
		t.Errorf("the title: %.30q", g)
	}
	for _, want := range []string{
		"`yars lint` runs the pattern and built-in rules", "`yars lint --all`", "90 s", "the rules as they are now",
		"`(?m)`", "Code blocks and tables are matched", "skips a part with no text",
		"## Dismissing a result", "the reviewer role", "that rule, that place and that quote",
		"not executable", "64 KB", "even when the script exits 0",
		"does not compile", "unknown check", "unknown target", "is not a configured section name",
		"AI rules skipped: no AI provider configured", "AI checks failed",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("the guide lacks %q", want)
		}
	}
	// the plain lint is not listed where scripts run
	if i := strings.Index(g, "| Runs |"); i < 0 || strings.Contains(g[i:i+strings.Index(g[i:], "\n")], "`yars lint` ·") {
		t.Error("the Runs row lists the plain yars lint")
	}
}

// The other pages agree with the code and with each other: the Go release,
// the data folder's path, what an unknown config key does, and where the
// Clone panel's command differs from the git guide's.
func TestDocsAgree(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if r := read("../README.md"); !strings.Contains(r, "Needs Go 1.27.2 or later.") || !strings.Contains(r, "[Wiki](https://github.com/abno525/yars/wiki)") {
		t.Error("README: the Go release or the wiki link")
	}
	if m := read("mcp.md"); strings.Contains(m, "/srv/yars-data") || !strings.Contains(m, "yars token add --data /srv/yars alice") {
		t.Error("mcp.md does not use deploy.md's data folder")
	}
	if c := read("config.md"); strings.Contains(c, "Unknown values are rejected") || !strings.Contains(c, "A key YARS does not know is ignored") {
		t.Error("config.md: what an unknown key does")
	}
	if g := read("git.md"); !strings.Contains(g, "The Clone panel clones into `yars`") {
		t.Error("git.md does not say where the Clone panel's folder name differs")
	}
	if d := read("deploy.md"); strings.Contains(d, "`docs/config.md`") || !strings.Contains(d, "[config.md](config.md)") {
		t.Error("deploy.md names config.md as text, not as a link")
	}
}

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
	// where results are kept, where not, and for how long (review)
	i = strings.Index(g, "## Stored results")
	stored := g[i : i+strings.Index(g[i+3:], "\n## ")+3]
	for _, want := range []string{"pre-commit", "A git push and `yars lint --all` run the script each time", "**Admin › System › Retention**"} {
		if !strings.Contains(stored, want) {
			t.Errorf("Stored results lacks %q", want)
		}
	}
	if !strings.Contains(ai, "`yars lint --all` sends the text each time") {
		t.Error("the AI rules section does not say where text is sent again")
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
	// and git's "redirecting" warning for a URL with a user name (M34 review);
	// a pentester or reviewer names their engagements, since git stops a
	// recursive clone at the first one they may not fetch, and a pull on
	// main keeps them there
	for _, want := range []string{"git clone --recurse-submodules", "git pull --recurse-submodules", "detached HEAD", "git submodule foreach -q git switch -q main", "warning: redirecting to", "Nothing is redirected",
		"git clone https://<server>/git/yars findings", "git submodule update --init engagements/<id> engagements/<id2>", "git submodule foreach -q git pull -q", "git submodule deinit engagements/<id>",
		// each line but the last ends with &&: a paste stops at the first
		// failure instead of running the rest in the current folder
		"git clone --recurse-submodules https://<server>/git/yars findings && cd findings &&\ngit submodule foreach -q git switch -q main\n",
		"git clone https://<server>/git/yars findings && cd findings &&\ngit submodule update --init engagements/<id> engagements/<id2> &&\ngit submodule foreach -q git switch -q main\n",
		// what tries an engagement never cloned again, and an engagement the
		// account was taken off (git fetches it while its repository is kept)
		"`git submodule update` try it again", "you were taken off", ".git/modules/engagements/<id>"} {
		if !strings.Contains(sec, want) {
			t.Errorf("the section lacks %q", want)
		}
	}
	// a token restricted to some engagements cannot clone the main repository
	if !strings.Contains(g[:strings.Index(g, "\n## ")], "restricted to some engagements cannot clone the main repository") {
		t.Error("the guide does not say a restricted token cannot clone the main repository")
	}
	m, err := Page("mcp")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m, "git clone https://alice:…@yars.example.com/git/yars findings && cd findings &&\ngit submodule update --init engagements/<id> &&") {
		t.Error("the MCP guide's clone is not chained")
	}
}
