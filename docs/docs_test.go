package docs

import (
	"bytes"
	"context"
	"io/fs"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/logs"
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
	for _, want := range []string{"## Checks and rules", "## Simple workflow", "AI rules skipped: no AI provider configured",
		"| A Check has no time limit of its own |",
		// as the rules guide has it: a push runs scripts and no AI rule, and
		// only `yars lint --all` runs either
		"| A git push and `yars lint --all` run every script each time, and `yars lint --all` sends the text to the AI provider each time |"} {
		if !strings.Contains(g, want) {
			t.Errorf("the limits page lacks %q", want)
		}
	}
	for _, bad := range []string{"`yars lint` run scripts", "push hook"} {
		if strings.Contains(g, bad) {
			t.Errorf("the limits page says %q: a push runs no AI rule and the plain yars lint no script", bad)
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
		"`exclude: code`", "Skip code box", "a fence that is never closed", "unknown exclude",
		"## Dismissing a result", "the reviewer role", "that rule, that place and that quote",
		"each script and each AI rule 90 s for itself", "fails alone", "90 s for all their scripts and AI questions together",
		"covers the matches that were there when it was made", "opens the result again", "Covers · By",
		"An error on your own finding: another reviewer or a director dismisses it", "A dismissal needs a reason", "a row in the audit log",
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
	if c := read("config.md"); strings.Contains(c, "is ignored") || !strings.Contains(c, "So is a key YARS does not know") ||
		!strings.Contains(c, "| `smtp.port` | number | 25 | 1 to 65535 |") {
		t.Error("config.md: what an unknown key does")
	}
	if g := read("git.md"); !strings.Contains(g, "The Clone panel clones into `yars`") {
		t.Error("git.md does not say where the Clone panel's folder name differs")
	}
	if d := read("deploy.md"); strings.Contains(d, "`docs/config.md`") || !strings.Contains(d, "[config.md](config.md)") {
		t.Error("deploy.md names config.md as text, not as a link")
	}
}

// The deploy guide makes the data folders private, hardens the unit without
// cutting off what the service writes, prunes backups, names the git it
// needs, and says what the admin flag and the simple workflow mean and how
// to take the data out.
func TestDeployGuideHardening(t *testing.T) {
	b, err := os.ReadFile("deploy.md")
	if err != nil {
		t.Fatal(err)
	}
	g := string(b)
	for _, want := range []string{
		"install -d -o yars -g yars -m 0700 /srv/yars\n", "install -d -o yars -g yars -m 0700 /srv/yars-restored\n",
		"NoNewPrivileges=yes", "ProtectSystem=strict", "ReadWritePaths=/srv/yars /var/lib/yars", "PrivateTmp=yes",
		"-mtime +30 -delete", "another machine",
		// rev-parse knows --end-of-options (Repo.Ref) from git 2.30 on
		"git 2.30 or later", "git filter-branch",
		"can run commands on the server",
		"the Team panel does not limit who sees an engagement",
		"## Uninstall", "yars backup --data /srv/yars --key --out",
		// the umask of 077 is the scripts' and pandoc's too, not only git's
		"rule scripts, script destinations and pandoc", "sets its own umask",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("the deploy guide lacks %q", want)
		}
	}
}

// Uninstalling copies the final backup out of the backup folder with a
// command, and the command that removes the data does not remove the
// backups with it: pasted in order, the blocks leave a copy. /etc/yars is
// optional, so its removal does not fail where it was never made.
func TestDeployGuideUninstallKeepsTheBackup(t *testing.T) {
	b, err := os.ReadFile("deploy.md")
	if err != nil {
		t.Fatal(err)
	}
	g := string(b)
	i := strings.Index(g, "\n## Uninstall\n")
	if i < 0 {
		t.Fatal("no Uninstall section")
	}
	sec := g[i:]
	out := strings.Index(sec, "--out /backups/yars-final.zip\n")
	cp := strings.Index(sec, "sudo install -m 0600 /backups/yars-final.zip /root/yars-final.zip\n")
	rm := strings.Index(sec, "sudo rm -r /srv/yars\n")
	last := strings.Index(sec, "sudo rm -r /backups\n")
	if out < 0 || cp < out || rm < cp || last < rm {
		t.Fatalf("the order is not backup (%d), copy (%d), remove the data (%d), remove the backups (%d)", out, cp, rm, last)
	}
	// the backups go in a block of their own, after a sentence in between
	if !strings.Contains(sec[rm:last], "```\n\n") || !strings.Contains(sec[rm:last], "another machine") {
		t.Error("the backup folder is removed in the same block as the data")
	}
	if !strings.Contains(sec, "sudo rm -rf /etc/yars\n") {
		t.Error("removing /etc/yars fails where it was never made")
	}
	for _, l := range strings.Split(sec, "\n") {
		if strings.Contains(l, " rm ") && strings.Contains(l, "/backups") && l != "sudo rm -r /backups" {
			t.Errorf("a removal names the backup folder among others: %s", l)
		}
	}
}

// logLine is one line of the service log as its handler writes it (text
// form), at a fixed time.
func logLine(t *testing.T, level slog.Level, msg string, args ...any) string {
	t.Helper()
	var buf bytes.Buffer
	r := slog.NewRecord(time.Date(2026, 11, 26, 14, 0, 3, 0, time.UTC), level, msg, 0)
	r.Add(args...)
	if err := logs.Handler(&buf, logs.Text, slog.LevelDebug).Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// The deploy guide's Logs section says how to read the service log: where
// it goes, the journalctl commands, the levels and fields, what a line never
// holds, the request ID, the background lines, yars status and the debug
// switch. Its example lines are what the handler writes, not the free text
// of before; the config page and the bug template name the same things.
func TestDeployGuideLogs(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	g := read("deploy.md")
	i := strings.Index(g, "\n## Logs\n")
	if i < 0 {
		t.Fatal("no Logs section")
	}
	sec := g[i+1:]
	if j := strings.Index(sec[3:], "\n## "); j >= 0 {
		sec = sec[:j+3]
	}
	for _, want := range []string{
		"journalctl -u yars -f", `journalctl -u yars --since "1 hour ago"`, "grep -E 'level=(WARN|ERROR)'", "grep req=4f2a9c1b",
		"YARS writes no log file", "`X-Request-ID`", "Request 4f2a9c1b",
		"| `error` |", "| `warn` |", "| `info` |", "| `debug` |",
		"| `req` |", "| `user` |", "| `token` |", "| `eng` |", "| `finding` |", "| `route` |", "| `status` |", "| `ms` |", "| `err` |",
		"never holds", "the setup code",
		"`check run finished`", "`ai call failed`", "`export finished`", "`webhook delivery failed; it is tried again`", "`notification email not sent`",
		"`push accepted`", "`push refused`", "`backup downloaded`", "`retention: the daily prune finished`", "`lock: a long wait for a repository's lock`", "`yars serving`",
		"`check run dropped`", "`restore: an uploaded backup is restored into a new folder`", "`restore: an uploaded backup is refused`",
		"`token notices: the daily run finished`", "`log: the debug level is switched on`", "`log: the debug level is switched off`",
		"`log: the debug level ended by itself`", "It needs `log.format: text`, the default.",
		"sudo -u yars yars status --data /srv/yars", "the last 200", "lost at a restart",
		"Debug level for 15 minutes", "`system.debug`",
		"`remote`", "`forwarded_for`", "ignoreip",
		// the example lines, as the handler writes them
		logLine(t, slog.LevelInfo, "request", "req", "4f2a9c1b", "method", "GET", "route", "GET /e/{eng}/f/{fid}", "status", 200, "ms", 12, "user", "alice", "eng", "acme", "finding", "F-002"),
		logLine(t, slog.LevelWarn, "login failed", "user", "alice", "remote", "127.0.0.1:53412", "forwarded_for", "203.0.113.9", "req", "7c1e0b3a"),
		logLine(t, slog.LevelWarn, "git login failed", "user", "alice", "remote", "127.0.0.1:53418", "forwarded_for", "203.0.113.9", "req", "0d5f9a21"),
		logLine(t, slog.LevelWarn, "login locked", "user", "alice", "until", "2026-11-26T14:15:00Z"),
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("the Logs section lacks %q", want)
		}
	}
	for _, bad := range []string{`login failed: user "alice" from`, "forwarded-for", "The address after `from`"} {
		if strings.Contains(g, bad) {
			t.Errorf("the deploy guide still has the old log form: %q", bad)
		}
	}
	// the Health list names the two new panels and the switch as the page does
	if h := g[strings.Index(g, "\n## Health\n"):i]; !strings.Contains(h, "**Current state**") || !strings.Contains(h, "**Log**") {
		t.Error("the Health section does not name the Current state and Log panels")
	}
	if c := read("config.md"); !strings.Contains(c, "Admin › System can set `debug` for 15 minutes without a restart") {
		t.Error("config.md does not name the debug switch")
	}
	tpl := read("../.github/ISSUE_TEMPLATE/bug_report.md")
	for _, want := range []string{"journalctl -u yars | grep req=", "Request 4f2a9c1b", "Use made-up data", "usernames and engagement IDs"} {
		if !strings.Contains(tpl, want) {
			t.Errorf("the bug template lacks %q", want)
		}
	}
	// plain words: no item or decision numbers of the plan
	for name, text := range map[string]string{"deploy.md": g, "config.md": read("config.md"), "CHANGELOG.md": read("../CHANGELOG.md"), "bug_report.md": tpl} {
		for _, bad := range []string{"L.3", "L.5", "L.6", "L.7", "Q15", "Q16", "Q17", "Phase L", "pre1"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s names %q", name, bad)
			}
		}
	}
	cl := read("../CHANGELOG.md")
	for _, want := range []string{"`yars status`", "Debug level for 15 minutes", "the last 200", "writes a line when it ends", "fail2ban"} {
		if !strings.Contains(cl, want) {
			t.Errorf("CHANGELOG lacks %q", want)
		}
	}
}

// The fail2ban patterns of the deploy guide take the address from the right
// place. A failed login's name comes first on its line and is the client's
// own text: a name that holds " remote=<another address>" must not choose
// the address that is banned. The patterns are run over lines the handler
// writes.
func TestDeployGuideFail2banPattern(t *testing.T) {
	b, err := os.ReadFile("deploy.md")
	if err != nil {
		t.Fatal(err)
	}
	var pats []*regexp.Regexp
	for _, l := range strings.Split(string(b), "\n") {
		src, ok := strings.CutPrefix(l, "failregex = ")
		if !ok {
			continue
		}
		// fail2ban's own parts: the journal's prefix, and the address it bans
		if !strings.HasPrefix(src, "^%(__prefix_line)s") || strings.Count(src, "<HOST>") != 1 {
			t.Fatalf("a failregex without the prefix or with no single <HOST>: %s", src)
		}
		src = strings.Replace(src, "%(__prefix_line)s", "", 1)
		src = strings.Replace(src, "<HOST>", `\[?(?P<host>[0-9a-fA-F:.]+?)\]?`, 1)
		re, err := regexp.Compile(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		pats = append(pats, re)
	}
	if len(pats) != 2 {
		t.Fatalf("%d failregex lines in the deploy guide, want the direct one and the one behind a proxy", len(pats))
	}
	direct, proxied := pats[0], pats[1]
	host := func(re *regexp.Regexp, line string) string {
		m := re.FindStringSubmatch(line)
		if m == nil {
			return ""
		}
		return m[re.SubexpIndex("host")]
	}
	const real, other = "203.0.113.9", "198.51.100.7"
	names := []string{"alice", "x remote=" + other + ":1", "x remote=" + other + ":1 y", `x" remote=` + other + `:1 y`, `x\" remote=` + other + `:1 y`,
		`a" level=WARN msg="login failed" user=b remote=` + other + ":1 ", "x\nremote=" + other + ":1 ", "remote=" + other + ":1", "",
		"x forwarded_for=" + other + " y", `x" remote=127.0.0.1:1 forwarded_for=` + other + " "}
	for _, name := range names {
		for _, msg := range []string{"login failed", "git login failed"} {
			line := logLine(t, slog.LevelWarn, msg, "user", name, "remote", real+":4711", "req", "4f2a9c1b")
			if got := host(direct, line); got != real {
				t.Errorf("direct: name %q bans %q, want %q\n%s", name, got, real, line)
			}
			// behind a proxy that sets the header to the client's address
			line = logLine(t, slog.LevelWarn, msg, "user", name, "remote", "127.0.0.1:53412", "forwarded_for", real, "req", "4f2a9c1b")
			if got := host(proxied, line); got != real {
				t.Errorf("behind a proxy: name %q bans %q, want %q\n%s", name, got, real, line)
			}
			if got := host(direct, line); got != "127.0.0.1" {
				t.Errorf("direct, behind a proxy: name %q gives %q, want the proxy's own address\n%s", name, got, line)
			}
		}
	}
	// an IPv6 address
	if got := host(direct, logLine(t, slog.LevelWarn, "login failed", "user", "alice", "remote", "[2001:db8::1]:4711")); got != "2001:db8::1" {
		t.Errorf("IPv6: %q", got)
	}
	// a header a client sent and the proxy appended to is a list: not matched
	if got := host(proxied, logLine(t, slog.LevelWarn, "login failed", "user", "alice", "remote", "127.0.0.1:1", "forwarded_for", other+", "+real)); got != "" {
		t.Errorf("a forwarded list bans %q", got)
	}
	// other lines ban nobody
	for _, line := range []string{
		logLine(t, slog.LevelWarn, "login locked", "user", "alice", "until", "2026-11-26T14:15:00Z"),
		logLine(t, slog.LevelInfo, "request", "req", "4f2a9c1b", "method", "POST", "route", "POST /login", "status", 401, "ms", 80),
		logLine(t, slog.LevelInfo, "login failed", "user", "alice", "remote", real+":1"),
		logLine(t, slog.LevelWarn, "request failed", "err", `msg="login failed" user=alice remote=`+other+":1 "),
	} {
		if host(direct, line) != "" || host(proxied, line) != "" {
			t.Errorf("a line that is no failed login bans an address: %s", line)
		}
	}
}

// The deploy guide names the health probe: its address, its two answers,
// that it needs no login and says no reason, and where the reason is.
func TestDeployGuideHealthProbe(t *testing.T) {
	b, err := os.ReadFile("deploy.md")
	if err != nil {
		t.Fatal(err)
	}
	g := string(b)
	i := strings.Index(g, "\n### Health probe\n")
	if i < 0 || i < strings.Index(g, "\n## Health\n") || i > strings.Index(g, "\n## Logs\n") {
		t.Fatal("no Health probe part in the Health section")
	}
	for _, want := range []string{"`GET /healthz`", "It needs no login.", "| `200` and `ok` |", "| `503` and `unavailable` |",
		"no version, no counts, no reason", "`health check failed`", "`health check passes again`", "static files, health probes,"} {
		if !strings.Contains(g, want) {
			t.Errorf("the deploy guide lacks %q", want)
		}
	}
}

// The deploy guide lists the account commands of the shell, says that
// disable is the usual way and that a deleted name stays taken, and names
// the last-admin rule with the words the command prints.
func TestDeployGuideAccountCommands(t *testing.T) {
	b, err := os.ReadFile("deploy.md")
	if err != nil {
		t.Fatal(err)
	}
	g := string(b)
	for _, want := range []string{
		"sudo -u yars yars users --data /srv/yars", "sudo -u yars yars disable --data /srv/yars bob\n", "sudo -u yars yars enable --data /srv/yars bob\n",
		"sudo -u yars yars userdel --data /srv/yars bob\n", "These commands work while the server runs",
		"`yars disable` is the usual way to take access away", "its name stays taken",
		"One admin who can sign in always remains", "`bob is the last admin: the admin flag stays`",
		"`yars help` lists every command", "`yars --version` prints the same",
	} {
		if !strings.Contains(g, want) {
			t.Errorf("the deploy guide lacks %q", want)
		}
	}
	if r, err := os.ReadFile("../README.md"); err != nil || !strings.Contains(string(r), "| `yars help` |") || !strings.Contains(string(r), "| `yars users` |") {
		t.Error("the README's commands lack yars help or yars users")
	}
}

// The git release the deploy guide asks for is the one the start checks
// (gitrepo.MinVersion): the page and the check cannot drift apart. The
// guide says the start checks it, and the changelog names the refusal.
func TestDeployGuideGitVersionIsTheCheckedOne(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	need := "git " + gitrepo.MinVersion() + " or later"
	d := read("deploy.md")
	for _, want := range []string{"**" + need + "**", "`yars serve` and `yars init` check the version first and do not start with an older git, or without git",
		"`git: the version does not read; the start goes on (YARS needs " + need + ")`"} {
		if !strings.Contains(d, want) {
			t.Errorf("the deploy guide lacks %q", want)
		}
	}
	if cl := read("../CHANGELOG.md"); !strings.Contains(cl, "`"+need+" is needed; this is git 2.25`") || !strings.Contains(cl, "`git is not on the PATH`") {
		t.Error("CHANGELOG does not name the refusal of an old git and of no git")
	}
}

// ciJob returns one job of the CI workflow: from its name to the next job's.
func ciJob(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	y := string(b)
	i := strings.Index(y, "\n  "+name+":\n")
	if i < 0 {
		t.Fatalf("ci.yml has no job %s", name)
	}
	job := y[i+1:]
	for _, l := range strings.SplitAfter(job, "\n")[1:] {
		// the next job's name, or the comment above it, at the jobs' indent
		if strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "   ") {
			return job[:strings.Index(job, "\n"+l)+1]
		}
	}
	return job
}

// The vulnerability job builds with the newest Go release, not with go.mod's
// minimum: an advisory against the standard library of the minimum, fixed in
// a later patch release, does not turn master red. The deploy guide tells
// the operator to build with that release too.
func TestCIVulnJobUsesTheNewestGo(t *testing.T) {
	j := ciJob(t, "vuln")
	if !strings.Contains(j, "govulncheck@v") {
		t.Fatalf("the vuln job: %s", j)
	}
	if strings.Contains(j, "go-version-file") || !strings.Contains(j, "go-version: stable\n") || !strings.Contains(j, "check-latest: true\n") {
		t.Errorf("the vuln job does not set up the newest Go release:\n%s", j)
	}
	// the other jobs keep go.mod's release
	for _, n := range []string{"test", "race"} {
		if !strings.Contains(ciJob(t, n), "go-version-file: go.mod\n") {
			t.Errorf("the %s job does not use go.mod's Go release", n)
		}
	}
	b, err := os.ReadFile("deploy.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "Build with the newest patch release") {
		t.Error("the deploy guide does not ask for the newest patch release")
	}
}

// The race job gives one package more than go test's ten minutes (the web
// package alone may need them under the detector), and the job more than
// its packages one after the other.
func TestCIRaceJobSetsItsTimeouts(t *testing.T) {
	j := ciJob(t, "race")
	if !strings.Contains(j, "run: go test -race -p 1 -timeout 45m ./internal/...\n") {
		t.Errorf("the race step has no timeout of its own:\n%s", j)
	}
	if !strings.Contains(j, "timeout-minutes: 120\n") {
		t.Errorf("the race job's own limit:\n%s", j)
	}
}

// go.mod names the module by the repository's address, and the README and
// the deploy guide install the command from that path: the documented
// `go install` works only while the two agree.
func TestInstallPathIsGoModsModule(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	first, _, _ := strings.Cut(read("../go.mod"), "\n")
	if first != "module github.com/abno525/yars" {
		t.Fatalf("go.mod's first line: %q", first)
	}
	install := "go install " + strings.TrimPrefix(first, "module ") + "/cmd/yars@latest\n"
	if !strings.Contains(read("../README.md"), install) {
		t.Errorf("README lacks %q", install)
	}
	d := read("deploy.md")
	if !strings.Contains(d, strings.TrimSuffix(install, "\n")) {
		t.Errorf("the deploy guide lacks %q", install)
	}
	// a go install build has no git revision to show: it shows its release
	if strings.Contains(d, "it shows the git revision instead") || !strings.Contains(d, "Built in a clone without `-ldflags`, it shows the git revision; installed with `go install` without them, the release it installed, such as `v1.0.0`.") {
		t.Error("the deploy guide does not say what version a go install build shows")
	}
}

// NOTICE names every module of go.mod at go.mod's version, and no other:
// a dependency update that leaves NOTICE behind fails here.
func TestNoticeListsGoModsModules(t *testing.T) {
	read := func(name string) []string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(string(b), "\n")
	}
	var mods []string
	in := false
	for _, l := range read("../go.mod") {
		f := strings.Fields(l)
		switch {
		case len(f) == 2 && f[0] == "require" && f[1] == "(":
			in = true
		case len(f) == 1 && f[0] == ")":
			in = false
		case len(f) >= 3 && f[0] == "require":
			mods = append(mods, f[1]+" "+f[2])
		case in && len(f) >= 2:
			mods = append(mods, f[0]+" "+f[1])
		}
	}
	if len(mods) == 0 {
		t.Fatal("no module read from go.mod")
	}
	var listed []string
	for _, l := range read("../NOTICE") {
		// a module line: "<host.tld/path> v<version>", at the start of the line
		f := strings.Fields(l)
		if len(f) == 2 && !strings.HasPrefix(l, " ") && strings.Contains(f[0], ".") && strings.Contains(f[0], "/") && strings.HasPrefix(f[1], "v") {
			listed = append(listed, l)
		}
	}
	for _, m := range mods {
		if !slices.Contains(listed, m) {
			t.Errorf("NOTICE lacks %q of go.mod", m)
		}
	}
	for _, l := range listed {
		if !slices.Contains(mods, l) {
			t.Errorf("NOTICE names %q, which go.mod does not", l)
		}
	}
}

// CONTRIBUTING lists every command CI's test job runs on a pull request,
// staticcheck at CI's pinned version among them: what passes there passes
// in CI.
func TestContributingListsCIsCommands(t *testing.T) {
	b, err := os.ReadFile("../CONTRIBUTING.md")
	if err != nil {
		t.Fatal(err)
	}
	c := string(b)
	n := 0
	for _, l := range strings.Split(ciJob(t, "test"), "\n") {
		cmd, ok := strings.CutPrefix(strings.TrimSpace(l), "run: ")
		if !ok || cmd == "|" {
			continue
		}
		n++
		if !strings.Contains(c, "\n"+cmd+"\n") {
			t.Errorf("CONTRIBUTING lacks CI's command %q", cmd)
		}
	}
	if n < 5 || !strings.Contains(c, "staticcheck@v") {
		t.Errorf("%d commands read from the test job; staticcheck must be one", n)
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
