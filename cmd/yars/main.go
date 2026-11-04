// Command yars: git-backed pentest findings tracker.
//
//	yars init <dir>
//	yars useradd --data <dir> --role <role> [--email e] <username>   (password read from stdin)
//	yars serve --data <dir> [--addr :8080]
//	yars lint --data <dir> [--all] [<engagement>[/<finding-dir>]]
package main

import (
	"bufio"
	"context"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/export"
	"yars/internal/finding"
	"yars/internal/gitrepo"
	"yars/internal/gitserve"
	"yars/internal/index"
	"yars/internal/mcp"
	"yars/internal/policy"
	"yars/internal/rules"
	"yars/internal/store"
	"yars/internal/web"
	"yars/internal/workflow"
)

var system = gitrepo.Author{Name: "yars", Email: "yars@yars.local"}

//go:embed rules_example.yaml
var exampleRules []byte

func exportRunner(dataDir string) *export.Runner {
	pandoc, _ := exec.LookPath("pandoc")
	return &export.Runner{Dir: filepath.Join(dataDir, ".yars", "exporters"), PandocPath: pandoc,
		HTTP: &http.Client{Timeout: 60 * time.Second}, Getenv: os.Getenv}
}

// cmdExport runs an exporter from the command line:
//
//	yars export --data <dir> --exporter <id> [--out file] [--mark --as <user>] <eng> [<finding-dir>…]
func cmdExport(args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	data := fs.String("data", ".", "data repo")
	exID := fs.String("exporter", "", "exporter id (file name in .yars/exporters without .yaml)")
	outPath := fs.String("out", "", "output file (default: <engagement>.<ext> in the current directory)")
	mark := fs.Bool("mark", false, "mark exported complete findings reported")
	as := fs.String("as", "", "director account used with --mark")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if fs.NArg() < 1 {
		return 2, fmt.Errorf("usage: yars export --exporter <id> <engagement> [<finding-dir>…]")
	}
	r, err := gitrepo.Open(*data)
	if err != nil {
		return 2, err
	}
	cfg, err := config.Load(r.Dir)
	if err != nil {
		return 2, err
	}
	run := exportRunner(r.Dir)
	exs, _ := export.Load(run.Dir)
	var ex *export.Exporter
	for i := range exs {
		if exs[i].ID == *exID {
			ex = &exs[i]
		}
	}
	if ex == nil {
		return 2, fmt.Errorf("unknown exporter %q", *exID)
	}
	st := store.New(r, cfg)
	e, err := st.Engagement(fs.Arg(0))
	if err != nil {
		return 2, err
	}
	refs, err := st.ListFindings(e.ID)
	if err != nil {
		return 2, err
	}
	var picked []store.FindingRef
	for _, ref := range refs {
		if (fs.NArg() > 1 && slices.Contains(fs.Args()[1:], ref.Dir)) || (fs.NArg() == 1 && slices.Contains(ex.Statuses, ref.F.Meta.Status)) {
			picked = append(picked, ref)
		}
	}
	if len(picked) == 0 {
		return 2, fmt.Errorf("no findings selected")
	}
	dirOf := map[*finding.Finding]string{}
	in := export.Input{Engagement: e, Cfg: cfg, Attachment: func(f *finding.Finding, rel string) ([]byte, bool) {
		b, err := st.ReadAttachment(e.ID, dirOf[f], rel)
		return b, err == nil
	}}
	for _, p := range picked {
		in.Findings = append(in.Findings, p.F)
		dirOf[p.F] = p.Dir
	}
	res, err := run.Run(context.Background(), *ex, in)
	if err != nil {
		return 1, err
	}
	if res.Pushed {
		fmt.Fprintln(out, "published:", res.URL)
	} else {
		dst := *outPath
		if dst == "" {
			dst = res.Filename
		}
		if err := os.WriteFile(dst, res.Data, 0o644); err != nil {
			return 1, err
		}
		fmt.Fprintln(out, "wrote", dst)
	}
	if *mark && ex.Marks() {
		users, _ := config.LoadUsers(r.Dir)
		u := config.User{}
		for _, x := range users {
			if x.Username == *as {
				u = x
			}
		}
		if u.Username == "" {
			return 1, fmt.Errorf("--mark needs --as <director account>")
		}
		for _, p := range picked {
			if p.F.Meta.Status == "complete" {
				if err := st.Transition(e.ID, p.Dir, workflow.Report, "", u); err != nil {
					fmt.Fprintln(out, "not marked", p.F.Meta.ID+":", err)
				} else {
					fmt.Fprintln(out, "marked reported", p.F.Meta.ID)
				}
			}
		}
	}
	return 0, nil
}

const usersIgnore = "# password hashes and API tokens stay on the server\n.yars/users.yaml\n.yars/tokens.yaml\n"

// runMCP serves MCP over stdio on a local clone as the given user. The
// server-side push policy re-checks everything when the commits are pushed.
func runMCP(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	data := fs.String("data", ".", "local clone of the data repo")
	user := fs.String("user", "", "your YARS username (commits are authored as this user)")
	role := fs.String("role", "pentester", "your role (pentester, reviewer, director)")
	email := fs.String("email", "", "git email (default <user>@yars.local, must match your YARS account)")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !store.ValidID(*user) || !config.ValidRole(*role) {
		return fmt.Errorf("usage: yars mcp --data <clone> --user <name> [--role pentester]")
	}
	r, err := gitrepo.Open(*data)
	if err != nil {
		return err
	}
	cfg, err := config.Load(r.Dir)
	if err != nil {
		return err
	}
	st := store.New(r, cfg)
	eng := rules.NewEngine(rules.DirFor(r.Dir), cfg)
	st.Linter = eng // same submit/approve gate as the server, before you push
	srv := &mcp.Server{Store: st, Index: index.New(st, r), Rules: eng, Cfg: cfg}
	return srv.ServeStdio(context.Background(), config.User{Username: *user, Role: *role, Email: *email}, in, out)
}

// cmdToken manages MCP API tokens: yars token add|list|revoke --data <dir> [<user>]
func cmdToken(args []string, out io.Writer) (int, error) {
	if len(args) == 0 {
		return 2, fmt.Errorf("usage: yars token add|list|revoke --data <dir> [<user>]")
	}
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	data := fs.String("data", ".", "data repo")
	if err := fs.Parse(args[1:]); err != nil {
		return 2, err
	}
	r, err := gitrepo.Open(*data)
	if err != nil {
		return 2, err
	}
	if err := untrackUsers(r); err != nil { // makes sure tokens.yaml is ignored
		return 1, err
	}
	tk, err := auth.LoadTokens(r.Dir)
	if err != nil {
		return 1, err
	}
	switch args[0] {
	case "list":
		for _, t := range tk.List() {
			fmt.Fprintf(out, "%s\tcreated %s\n", t.User, t.Created)
		}
		return 0, nil
	case "add", "revoke":
		if fs.NArg() != 1 {
			return 2, fmt.Errorf("usage: yars token %s --data <dir> <user>", args[0])
		}
		name := fs.Arg(0)
		users, _ := config.LoadUsers(r.Dir)
		if !slices.ContainsFunc(users, func(u config.User) bool { return u.Username == name }) && args[0] == "add" {
			return 1, fmt.Errorf("unknown user %s", name)
		}
		if args[0] == "revoke" {
			return 0, tk.Revoke(r.Dir, name)
		}
		tok, err := tk.Add(r.Dir, name)
		if err != nil {
			return 1, err
		}
		fmt.Fprintf(out, "token for %s (shown once; active immediately):\n%s\n", name, tok)
		return 0, nil
	}
	return 2, fmt.Errorf("unknown token command %q", args[0])
}

// untrackUsers makes sure .yars/users.yaml is ignored and not tracked, so a
// clone never carries password hashes (older repos committed it; their
// history still does — rewrite it if that matters).
func untrackUsers(r *gitrepo.Repo) error {
	gi := filepath.Join(r.Dir, ".gitignore")
	b, _ := os.ReadFile(gi)
	if !strings.Contains(string(b), ".yars/users.yaml") || !strings.Contains(string(b), ".yars/tokens.yaml") {
		next := string(b)
		if next != "" && !strings.HasSuffix(next, "\n") {
			next += "\n"
		}
		for _, l := range strings.Split(strings.TrimSpace(usersIgnore), "\n") {
			if !strings.Contains(next, l) {
				next += l + "\n"
			}
		}
		if err := os.WriteFile(gi, []byte(next), 0o644); err != nil {
			return err
		}
		if err := r.Commit([]string{".gitignore"}, "ignore users.yaml (password hashes stay on the server)", system); err != nil {
			return err
		}
	}
	if r.Tracked(".yars/users.yaml") {
		return r.Untrack(".yars/users.yaml", "stop tracking users.yaml (password hashes stay on the server)", system)
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// hookCmd is the command line the git pre-receive hook execs.
func hookCmd(bin, dataDir string) string {
	abs, _ := filepath.Abs(dataDir)
	return shellQuote(bin) + " hook pre-receive --data " + shellQuote(abs)
}

// cmdHook implements "yars hook pre-receive": reads "<old> <new> <ref>"
// lines from git, checks them against the server's rules and prints one
// "yars: <problem>" line per rejection reason. Exit 1 rejects the push.
func cmdHook(args []string, in io.Reader, errOut io.Writer) int {
	if len(args) == 0 || args[0] != "pre-receive" {
		fmt.Fprintln(errOut, "yars: usage: yars hook pre-receive --data <dir>")
		return 2
	}
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	data := fs.String("data", ".", "data repo")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	// git runs hooks with a possibly relative GIT_DIR; our git calls use -C.
	if gd := os.Getenv("GIT_DIR"); gd != "" && !filepath.IsAbs(gd) {
		if abs, err := filepath.Abs(gd); err == nil {
			os.Setenv("GIT_DIR", abs)
		}
	}
	fail := func(msg string) int {
		fmt.Fprintln(errOut, "yars: "+msg)
		return 1
	}
	user := os.Getenv("REMOTE_USER")
	if user == "" {
		return fail("pushes must go through the YARS server (no authenticated user)")
	}
	r, err := gitrepo.Open(*data)
	if err != nil {
		return fail(err.Error())
	}
	cfg, err := config.Load(r.Dir)
	if err != nil {
		return fail(err.Error())
	}
	users, err := config.LoadUsers(r.Dir)
	if err != nil {
		return fail(err.Error())
	}
	var ups []policy.Update
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 3 {
			ups = append(ups, policy.Update{Old: f[0], New: f[1], Ref: f[2]})
		}
	}
	c := &policy.Checker{Repo: r, Cfg: cfg, Users: users, Linter: rules.NewEngine(rules.DirFor(r.Dir), cfg)}
	ps := c.Check(user, ups)
	for _, p := range ps {
		fmt.Fprintln(errOut, "yars: "+p)
	}
	if len(ps) > 0 {
		return 1
	}
	return 0
}

// cmdLint checks findings against the style rules. Exit code 1 when any
// error-level violation is found.
func cmdLint(args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	data := fs.String("data", ".", "data repo")
	fs.Bool("fast", true, "only regex and built-in rules (the default)")
	all := fs.Bool("all", false, "also run script and AI rules (runs code from the repo and sends text to the AI provider)")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	r, err := gitrepo.Open(*data)
	if err != nil {
		return 2, err
	}
	cfg, err := config.Load(r.Dir)
	if err != nil {
		return 2, err
	}
	st := store.New(r, cfg)
	eng := rules.NewEngine(rules.DirFor(r.Dir), cfg)
	kinds := rules.Fast
	if *all {
		kinds = rules.All
	}
	scopeEng, scopeDir, _ := strings.Cut(fs.Arg(0), "/")
	engs, err := st.ListEngagements()
	if err != nil {
		return 2, err
	}
	code, checked := 0, 0
	for _, e := range engs {
		if scopeEng != "" && e.ID != scopeEng {
			continue
		}
		refs, err := st.ListFindings(e.ID)
		if err != nil {
			return 2, err
		}
		for _, ref := range refs {
			if scopeDir != "" && ref.Dir != scopeDir {
				continue
			}
			checked++
			for _, v := range eng.Lint(context.Background(), ref.F, kinds) {
				line := fmt.Sprintf("%s/%s %s %s: %s", e.ID, ref.F.Meta.ID, v.Level, v.Rule, v.Message)
				if v.Quote != "" {
					line += fmt.Sprintf(" (%q)", v.Quote)
				}
				fmt.Fprintln(out, line+" ["+v.Target+"]")
				if v.Level == "error" {
					code = 1
				}
			}
		}
	}
	fmt.Fprintf(out, "%d finding(s) checked\n", checked)
	return code, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: yars init <dir> | useradd --data <dir> --role <role> <username> | serve --data <dir> [--addr :8080] | lint --data <dir> [--all] [eng[/finding]] | export --data <dir> --exporter <id> <eng> | token add|list|revoke --data <dir> <user> | mcp --data <clone> --user <name>")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "useradd":
		err = cmdUseradd(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "export":
		code, xerr := cmdExport(os.Args[2:], os.Stdout)
		if xerr != nil {
			fmt.Fprintln(os.Stderr, "yars:", xerr)
		}
		os.Exit(code)
	case "mcp":
		err = runMCP(os.Args[2:], os.Stdin, os.Stdout)
	case "token":
		code, terr := cmdToken(os.Args[2:], os.Stdout)
		if terr != nil {
			fmt.Fprintln(os.Stderr, "yars:", terr)
		}
		os.Exit(code)
	case "hook":
		os.Exit(cmdHook(os.Args[2:], os.Stdin, os.Stderr))
	case "lint":
		code, lerr := cmdLint(os.Args[2:], os.Stdout)
		if lerr != nil {
			fmt.Fprintln(os.Stderr, "yars:", lerr)
		}
		os.Exit(code)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "yars:", err)
		os.Exit(1)
	}
}

func cmdInit(args []string) error {
	if len(args) != 1 {
		usage()
	}
	dir := args[0]
	r, err := gitrepo.Init(dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(config.ConfigPath(dir)); err == nil {
		return fmt.Errorf("%s is already initialised", dir)
	}
	if err := os.MkdirAll(filepath.Join(dir, "engagements"), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(config.ConfigPath(dir)), 0o755); err != nil {
		return err
	}
	b, _ := yaml.Marshal(config.Default())
	if err := os.MkdirAll(rules.DirFor(dir), 0o755); err != nil {
		return err
	}
	files := map[string][]byte{
		config.ConfigPath(dir):                         b,
		filepath.Join(dir, ".gitignore"):               []byte(usersIgnore),
		filepath.Join(dir, "engagements", ".gitkeep"):  nil,
		filepath.Join(rules.DirFor(dir), "style.yaml"): exampleRules,
	}
	for p, c := range files {
		if err := os.WriteFile(p, c, 0o644); err != nil {
			return err
		}
	}
	exDir := filepath.Join(dir, ".yars", "exporters")
	if err := os.MkdirAll(exDir, 0o755); err != nil {
		return err
	}
	for name, body := range exampleExporters {
		if err := os.WriteFile(filepath.Join(exDir, name), []byte(body), 0o644); err != nil {
			return err
		}
	}
	// users.yaml holds password hashes: kept on the server only, never in git
	if err := config.SaveUsers(dir, []config.User{}); err != nil {
		return err
	}
	if err := r.Commit([]string{".yars/config.yaml", ".yars/rules", ".yars/exporters", ".gitignore", "engagements"}, "init", system); err != nil {
		return err
	}
	fmt.Println("initialised", dir)
	return nil
}

func cmdUseradd(args []string) error {
	fs := flag.NewFlagSet("useradd", flag.ExitOnError)
	data := fs.String("data", ".", "data repo")
	role := fs.String("role", "pentester", "pentester|reviewer|director")
	email := fs.String("email", "", "email for git authorship")
	fs.Parse(args)
	if fs.NArg() != 1 {
		usage()
	}
	name := fs.Arg(0)
	if !config.ValidRole(*role) {
		fmt.Fprintf(os.Stderr, "yars: invalid role %q (want %s)\n", *role, strings.Join(config.Roles, ", "))
		os.Exit(2)
	}
	if !store.ValidID(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	r, err := gitrepo.Open(*data)
	if err != nil {
		return err
	}
	users, err := config.LoadUsers(r.Dir)
	if err != nil {
		return err
	}
	for _, u := range users {
		if u.Username == name {
			return fmt.Errorf("user %s already exists", name)
		}
	}
	fmt.Fprint(os.Stderr, "password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		return fmt.Errorf("empty password (%v)", err)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	users = append(users, config.User{Username: name, Email: *email, Role: *role, PasswordHash: hash})
	if err := config.SaveUsers(r.Dir, users); err != nil {
		return err
	}
	if err := untrackUsers(r); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "\nadded", name, "as", *role)
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	data := fs.String("data", ".", "data repo")
	addr := fs.String("addr", ":8080", "listen address")
	fs.Parse(args)
	r, err := gitrepo.Open(*data)
	if err != nil {
		return err
	}
	cfg, err := config.Load(r.Dir)
	if err != nil {
		return err
	}
	users, err := config.LoadUsers(r.Dir)
	if err != nil {
		return err
	}
	if len(users) == 0 {
		log.Println("warning: no users; add one with: yars useradd --data", *data, "--role director <name>")
	}
	st := store.New(r, cfg)
	eng := rules.NewEngine(rules.DirFor(r.Dir), cfg)
	st.Linter = eng
	au := auth.New(users)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := untrackUsers(r); err != nil {
		return fmt.Errorf("untrack users.yaml: %w", err)
	}
	gs := &gitserve.Server{Repo: r, Auth: au, HookCmd: hookCmd(exe, r.Dir)}
	if cfg.AI.APIKeyEnv != "" {
		gs.InheritEnv = []string{cfg.AI.APIKeyEnv} // AI rules run on pushes too
	}
	if err := gs.Setup(); err != nil {
		return fmt.Errorf("git setup: %w", err)
	}
	tokens, err := auth.LoadTokens(r.Dir)
	if err != nil {
		return err
	}
	ix := index.New(st, r)
	mcpSrv := &mcp.Server{Store: st, Index: ix, Rules: eng, Cfg: cfg, Users: au.Users}
	lookup := func(name string) (config.User, bool) {
		for _, u := range au.Users() {
			if u.Username == name {
				return u, true
			}
		}
		return config.User{}, false
	}
	srv := &web.Server{Store: st, Index: ix, Auth: au, Cfg: cfg, Rules: eng, Git: gs.Handler(), Export: exportRunner(r.Dir),
		MCP: mcpSrv.HTTPHandler(tokens, lookup)}
	log.Printf("yars serving %s on %s", r.Dir, *addr)
	return http.ListenAndServe(*addr, srv.Handler())
}
