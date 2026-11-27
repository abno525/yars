// Command yars: git-backed pentest findings tracker. Finding content lives
// in git; accounts, workflow state and chat in .yars/yars.db (server only).
//
//	yars init [--simple] <dir>   (--simple: the simple workflow, fixed after init)
//	yars use [<dir>]   (set or show the default data folder)
//	yars useradd --data <dir> --role <role> [--email e] <username>
//	yars passwd|userdel|unlock --data <dir> <username>; yars role --data <dir> <username> <role>
//	  (useradd, passwd: the password is asked twice on a terminal, unseen; a
//	  piped one must be changed at the next login)
//	yars admin --data <dir> <username> on|off
//	yars serve --data <dir> [--addr :8080] [--tls-cert <file> --tls-key <file>] [--https]
//	yars status --data <dir>   (what the running server does now, read over a socket in the data folder)
//	yars migrate --data <dir>   (move state and chat from files into the database)
//	yars backup --data <dir> [--key] --out <file.zip>   (works while the server runs)
//	yars restore --from <file.zip> --data <new dir>   (--data is required: never the default)
//	yars lint --data <dir> [--all] [<engagement>[/<finding>]]   (a finding by folder, ID or number)
//	yars seed [--simple] --data <new dir> [--engagements 2] [--findings 20] [--messages 50]   (development data; prints the accounts' random password)
//
// Flags come before the other arguments. Without --data, a command works
// on $YARS_DATA, else the folder set with yars use (data: in
// $XDG_CONFIG_HOME/yars/config.yaml, or ~/.config/yars/config.yaml), else
// the current folder. seed always needs --data; mcp's --data is a local
// clone (default: the current folder).
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/export"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/mcp"
	"github.com/abno525/yars/internal/outbound"
	"github.com/abno525/yars/internal/policy"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/secret"
	"github.com/abno525/yars/internal/seed"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/workflow"
)

var system = gitrepo.Author{Name: "yars", Email: "yars@yars.local"}

// exportRunner runs the destinations of a data folder. Its HTTP client
// sends a destination's key and the findings to the configured address
// only: a redirect to another host is refused (outbound.Client).
func exportRunner(dataDir string) *export.Runner {
	pandoc, _ := exec.LookPath("pandoc")
	return &export.Runner{Dir: filepath.Join(dataDir, ".yars", "exporters"), PandocPath: pandoc,
		HTTP: outbound.Client(60 * time.Second), Getenv: os.Getenv}
}

// cmdExport runs an exporter from the command line:
//
//	yars export --data <dir> --exporter <id> [--out file] [--force] [--mark --as <user>] <eng> [<finding-dir>…]
//
// The file is written for the user alone (0600) and replaces none without
// --force. A device or a pipe named by --out is written into.
func cmdExport(args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	data := dataFlag(fs)
	exID := fs.String("exporter", "", "exporter id (file name in .yars/exporters without .yaml)")
	outPath := fs.String("out", "", "output file (default: <engagement>.<ext> in the current directory)")
	force := fs.Bool("force", false, "replace the output file when it exists")
	mark := fs.Bool("mark", false, "mark exported complete findings reported")
	as := fs.String("as", "", "director account used with --mark")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if fs.NArg() < 1 {
		return 2, fmt.Errorf("usage: yars export --exporter <id> <engagement> [<finding-dir>…]")
	}
	for _, a := range fs.Args()[1:] { // the flag package stops at the engagement
		if strings.HasPrefix(a, "-") {
			return 2, fmt.Errorf("usage: yars export [flags] <engagement> [<finding>…]: flags go before the engagement; %q is after it", a)
		}
	}
	r, err := openData(fs, *data)
	if err != nil {
		return 2, err
	}
	cfg, err := config.Load(r.Dir)
	if err != nil {
		return 2, err
	}
	run := exportRunner(r.Dir)
	exs, loadErrs := export.Load(run.Dir)
	var ex *export.Exporter
	for i := range exs {
		if exs[i].ID == *exID {
			ex = &exs[i]
		}
	}
	if ex == nil {
		for _, err := range loadErrs { // its file is there but does not load: say why
			if strings.HasPrefix(err.Error(), *exID+".yaml: ") {
				return 2, err
			}
		}
		return 2, fmt.Errorf("unknown exporter %q", *exID)
	}
	// a file that is there is not replaced: said before anything runs (a
	// destination that publishes writes no file)
	if *outPath != "" && !*force && !ex.Service() {
		if _, err := os.Lstat(*outPath); err == nil && !writesThrough(*outPath) {
			return 2, existsErr(*outPath)
		}
	}
	d, err := existingDB(r.Dir)
	if err != nil {
		return 2, err
	}
	if d != nil {
		defer d.Close()
	}
	// --mark's account is checked before anything is exported
	var marker config.User
	if *mark && ex.Marks() {
		if d == nil {
			return 2, fmt.Errorf("--mark needs the server's data directory (workflow state is in its database)")
		}
		u, ok, _ := d.User(*as)
		if !ok {
			if cfg.Simple() { // every account is a director: no role to name
				return 2, fmt.Errorf("--mark needs --as <account>")
			}
			return 2, fmt.Errorf("--mark needs --as <director account>")
		}
		if !workflow.AtLeast(u, "director") {
			return 2, fmt.Errorf("--mark needs --as <director account>: %s is a %s", u.Username, u.Role)
		}
		marker = u
	}
	st := store.New(r, cfg, d)
	st.Logger = termLogger()
	e, err := st.Engagement(fs.Arg(0))
	if err != nil {
		return 2, err
	}
	refs, err := st.ListFindings(e.ID)
	if err != nil {
		return 2, err
	}
	// named findings, as the website names them: folder, ID or number
	named := map[string]bool{}
	var missing []string
	for _, name := range fs.Args()[1:] {
		ref, err := st.Finding(e.ID, name)
		if errors.Is(err, store.ErrNotFound) {
			missing = append(missing, name)
			continue
		} else if err != nil {
			return 2, err
		}
		// only finished findings leave YARS, as on the website (R10)
		if s := ref.F.Meta.Status; s != "complete" && s != "reported" {
			return 2, fmt.Errorf("%s is %s: only complete and reported findings are exported", ref.F.Meta.ID, s)
		} else if !slices.Contains(ex.Statuses, s) { // and only those the exporter takes
			return 2, fmt.Errorf("%s is %s: %s exports %s findings only", ref.F.Meta.ID, s, ex.ID, strings.Join(ex.Statuses, " and "))
		}
		named[ref.Dir] = true
	}
	if len(missing) > 0 {
		return 2, fmt.Errorf("no finding matches %s", strings.Join(missing, ", "))
	}
	var picked []store.FindingRef
	for _, ref := range refs {
		if !workflow.Active(ref.F.Meta.Status) {
			continue // withdrawn findings are never exported
		}
		if (fs.NArg() > 1 && named[ref.Dir]) || (fs.NArg() == 1 && slices.Contains(ex.Statuses, ref.F.Meta.Status)) {
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
	for _, n := range cfg.ReportSections { // the Report tab
		body, err := st.ReportSection(e.ID, n)
		if err != nil {
			return 1, err
		}
		in.Report = append(in.Report, export.ReportText{Name: n, Body: body})
	}
	for _, p := range picked {
		in.Findings = append(in.Findings, p.F)
		dirOf[p.F] = p.Dir
	}
	// a service destination updates the page or issue it made before, as the
	// website does and from the same rows: a finding's own, or, for the one
	// Confluence page of several findings, the row without a finding
	remoteKey := func(id string) string {
		if ex.Type == "confluence" && len(picked) > 1 {
			return export.PageKey
		}
		return id
	}
	if ex.Service() && d != nil {
		in.Known = map[string]export.Remote{}
		for _, p := range picked {
			k := remoteKey(p.F.Meta.ID)
			if _, seen := in.Known[k]; seen {
				continue
			}
			rm, ok, err := d.ExportRemote(ex.ID, e.ID, k)
			if err != nil {
				return 1, err
			}
			if ok && rm.Target == ex.Target() {
				in.Known[k] = export.Remote{ID: rm.RemoteID, Version: rm.Version}
			}
		}
	}
	res, err := run.Run(context.Background(), *ex, in)
	// with an error too: the page a failed push made, which the next run fills
	if d != nil {
		stored := map[string]bool{}
		for _, it := range res.Items {
			k := remoteKey(it.ID)
			if it.Remote.ID == "" || stored[k] {
				continue
			}
			stored[k] = true
			rm := db.ExportRemote{Destination: ex.ID, Eng: e.ID, Finding: k, Target: ex.Target(), RemoteID: it.Remote.ID, Version: it.Remote.Version, URL: it.URL}
			if err := d.SetExportRemote(rm); err != nil {
				// the push stands; the next run would make another page or issue
				fmt.Fprintln(out, "not remembered:", err)
			}
		}
	}
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
		if err := writeExport(dst, res.Data, *force); err != nil {
			return 1, err
		}
		fmt.Fprintln(out, "wrote", dst)
	}
	if d != nil {
		d.Audit("cli", "export", e.ID, fmt.Sprintf("%s, %d findings", ex.ID, len(picked)))
	}
	code := 0
	if *mark && !ex.Marks() {
		// said, so the command does not look as if it marked
		fmt.Fprintln(out, "not marked:", ex.ID, "has mark_reported off")
	}
	if *mark && ex.Marks() {
		for _, p := range picked {
			if p.F.Meta.Status == "complete" {
				if err := st.Transition(e.ID, p.Dir, workflow.Report, "", marker); err != nil {
					fmt.Fprintln(out, "not marked", p.F.Meta.ID+":", err)
					code = 1 // the export stands; the others are still marked
				} else {
					fmt.Fprintln(out, "marked reported", p.F.Meta.ID)
				}
			}
		}
	}
	return code, nil
}

func existsErr(file string) error {
	return fmt.Errorf("%s exists already (use --force to replace it)", file)
}

// writesThrough says dst names something that is there and is no file to
// protect or replace: a device, a pipe or a socket (/dev/null, a FIFO,
// /dev/stdout into a pipe or a terminal). A link is followed here, so a
// link to a file or a folder is not one of them.
func writesThrough(dst string) bool {
	info, err := os.Stat(dst)
	return err == nil && !info.Mode().IsRegular() && !info.IsDir()
}

// writeExport writes an export file for the user alone (0600). It replaces
// no file; with force it does, through a new file renamed into place, so
// the old file's mode is not kept and a link is replaced, not followed.
// A device or a pipe is written into, with or without force, and stays
// what it is.
func writeExport(dst string, data []byte, force bool) error {
	var f *os.File
	var err error
	if writesThrough(dst) {
		if f, err = os.OpenFile(dst, os.O_WRONLY, 0); err != nil {
			return err
		}
		// a file put there since the look is not written into
		if info, serr := f.Stat(); serr != nil || info.Mode().IsRegular() || info.IsDir() {
			f.Close()
			return existsErr(dst)
		}
		_, err = f.Write(data)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	}
	if force {
		f, err = os.CreateTemp(filepath.Dir(dst), "."+filepath.Base(dst)+".*") // 0600
	} else if f, err = os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); os.IsExist(err) {
		return existsErr(dst)
	}
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && force {
		err = os.Rename(f.Name(), dst)
	}
	if err != nil {
		os.Remove(f.Name())
	}
	return err
}

// serverIgnore keeps server-only files out of git: the database (accounts,
// tokens, sessions, workflow state, chat) and the pre-database account files.
const serverIgnore = "# accounts, tokens, chat and workflow state stay on the server\n.yars/yars.db*\n.yars/users.yaml\n.yars/tokens.yaml\n.yars/secret.key\n"

// oldIgnoreComments are the comments earlier versions wrote over the same
// lines (cef68f5, 70f67a6).
var oldIgnoreComments = []string{"# password hashes stay on the server", "# password hashes and API tokens stay on the server"}

// dataDB opens (creating if needed) the data directory's database. A new
// one (yars.db missing: deleted, or the folder copied without it) holds no
// accounts or states yet, so it takes the workflow config.yaml names and
// records it, as yars init does (workflowSetting).
func dataDB(dir string) (*db.DB, error) {
	_, err := os.Stat(db.Path(dir))
	fresh := errors.Is(err, os.ErrNotExist)
	d, err := db.Open(db.Path(dir))
	if err != nil || !fresh || fileWorkflow(dir) != config.WorkflowSimple {
		return d, err
	}
	if err := d.SetSetting(workflowSetting, config.WorkflowSimple); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// fileWorkflow is the workflow config.yaml in dir names, read through its
// workflow key alone (the rest of the file may be broken): standard when
// the file or the key does not read.
func fileWorkflow(dir string) string {
	var k struct {
		Workflow string `yaml:"workflow"`
	}
	b, err := os.ReadFile(config.ConfigPath(dir))
	if err != nil || yaml.Unmarshal(b, &k) != nil || k.Workflow != config.WorkflowSimple {
		return config.WorkflowStandard
	}
	return config.WorkflowSimple
}

// termLogger is the logger of a command run at a terminal (export, lint,
// mcp): what the store and the rules would write to the service log of yars
// serve (a finding or an engagement skipped because it does not read) goes
// to stderr as text, warnings and errors only. The command's own answers
// stay plain lines on stdout and stderr.
func termLogger() *slog.Logger { return logs.New(os.Stderr, logs.Text, slog.LevelWarn) }

// existingDB opens the database only when there is one (a clone has none).
func existingDB(dir string) (*db.DB, error) {
	if _, err := os.Stat(db.Path(dir)); err != nil {
		return nil, nil
	}
	return dataDB(dir)
}

// runMCP serves MCP over stdio on a local clone as the given user: content
// only (workflow and chat are on the server). The server-side push policy
// re-checks everything when the commits are pushed.
func runMCP(args []string, in io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	data := fs.String("data", ".", "local clone of the data repo")
	user := fs.String("user", "", "your YARS username (commits are authored as this user)")
	role := fs.String("role", "pentester", "your role (pentester, reviewer, director); the simple workflow has none")
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
	u, err := mcpUser(cfg, flagGiven(fs, "role"), config.User{Username: *user, Role: *role, Email: *email})
	if err != nil {
		return err
	}
	// stdout speaks the protocol: what the parts log goes to stderr
	lg := termLogger()
	st := store.New(r, cfg, nil)
	st.Logger = lg
	eng := rules.NewEngine(rules.DirFor(r.Dir), cfg)
	eng.SetLogger(lg)
	st.Linter = eng
	srv := mcpServer(st, index.New(st, r), eng, cfg, nil)
	srv.Logger = lg
	return srv.ServeStdio(context.Background(), u, in, out)
}

// mcpUser is the account yars mcp serves as: u as the flags give it, but a
// director in the simple workflow, as every account of it is stored
// (roleGiven: --role was set, and then only director may be).
func mcpUser(cfg config.Config, roleGiven bool, u config.User) (config.User, error) {
	if cfg.Simple() {
		role, err := simpleRole(roleGiven, u.Role)
		if err != nil {
			return config.User{}, err
		}
		u.Role = role
	}
	return u, nil
}

// mcpServer is the MCP server of yars serve and yars mcp, naming the
// build's version (users nil: a clone, where the push policy validates
// reviewers).
func mcpServer(st *store.Store, ix *index.Index, eng *rules.Engine, cfg config.Config, users func() []config.User) *mcp.Server {
	return &mcp.Server{Store: st, Index: ix, Rules: eng, Cfg: cfg, Users: users, Version: buildVersion()}
}

// cmdToken manages MCP API tokens: yars token add|list|revoke --data <dir> [<user>]
func cmdToken(args []string, out io.Writer) (int, error) {
	if len(args) == 0 {
		return 2, fmt.Errorf("usage: yars token add|list|revoke --data <dir> [<user>]")
	}
	fs := flag.NewFlagSet("token", flag.ContinueOnError)
	data := dataFlag(fs)
	kind := fs.String("kind", db.TokenMCP, "add: mcp (the /mcp endpoint) or git (git over HTTP, as the password)")
	scopes := fs.String("scopes", db.ScopeAll, "add: all, read, or actions ("+strings.Join(db.TokenActions, ",")+"; the simple workflow has no reviewers)")
	name := fs.String("name", "", "add: a name for the token")
	engs := fs.String("engagements", "", "add: comma-separated engagement ids (default: all)")
	days := fs.Int("days", tokenDays, "add: expires after this many days (0 = never)")
	expires := fs.String("expires", "", "add: expires at the end of this day, YYYY-MM-DD in UTC, or never (instead of --days)")
	id := fs.Int64("id", 0, "revoke: only this token (default: every token of the user)")
	fs.SetOutput(out)
	if err := fs.Parse(args[1:]); err != nil {
		return 2, err
	}
	expiry := ""
	if args[0] == "add" { // a mistake in the flags makes no token and touches nothing
		var err error
		if expiry, err = tokenExpiry(*days, *expires, flagGiven(fs, "days"), flagGiven(fs, "expires"), time.Now().UTC()); err != nil {
			return 2, err
		}
	}
	r, err := openData(fs, *data)
	if err != nil {
		return 2, err
	}
	if err := ensureIgnored(r); err != nil {
		return 1, err
	}
	d, err := dataDB(r.Dir)
	if err != nil {
		return 1, err
	}
	defer d.Close()
	tk := auth.NewTokens(d)
	switch args[0] {
	case "list":
		for _, t := range tk.List() {
			e := strings.Join(t.Engagements, ",")
			if e == "" {
				e = "all"
			}
			exp := t.Expires
			if exp == "" {
				exp = "never"
			}
			fmt.Fprintf(out, "%d\t%s\t%s\t…%s\t%s\tscopes %s\tengagements %s\texpires %s\tcreated %s\n",
				t.ID, t.User, t.Kind, t.Last4, t.Name, strings.Join(t.Scopes, ","), e, exp, t.Created)
		}
		return 0, nil
	case "add", "revoke":
		if fs.NArg() != 1 {
			return 2, fmt.Errorf("usage: yars token %s --data <dir> [flags] <user>", args[0])
		}
		user := fs.Arg(0)
		if _, ok, err := d.User(user); err != nil {
			return 1, err
		} else if !ok { // a typo in revoke must not look like success
			return 1, fmt.Errorf("unknown user %s", user)
		}
		if args[0] == "revoke" {
			if *id != 0 {
				return 0, tk.RevokeID("cli", *id, user)
			}
			return 0, tk.Revoke("cli", user)
		}
		spec := db.TokenSpec{Name: *name, Kind: *kind, Scopes: splitList(*scopes)}
		if slices.Contains(spec.Scopes, "reviewers") {
			// the simple workflow (the database's workflow setting, which
			// yars init writes) has no reviewers, so no scope to assign
			// them: Settings › Tokens offers none either
			if w, err := d.Setting("workflow"); err != nil {
				return 1, err
			} else if w == config.WorkflowSimple {
				return 1, errors.New("token scope reviewers: the simple workflow has no reviewers")
			}
		}
		spec.Engagements = splitList(*engs)
		spec.Expires = expiry
		tok, info, err := tk.Create("cli", user, spec)
		if err != nil {
			return 1, err
		}
		until := "never expires"
		if info.Expires != "" {
			until = "expires " + strings.Replace(info.Expires, "T", " ", 1)
		}
		fmt.Fprintf(out, "token #%d for %s (%s; %s; shown once; active immediately):\n%s\n", info.ID, user, info.Kind, until, tok)
		return 0, nil
	}
	return 2, fmt.Errorf("unknown token command %q", args[0])
}

// tokenDays is how long a token of yars token add lives when no flag says
// otherwise: the choice Settings › Tokens › New token starts with.
const tokenDays = 90

// tokenExpiry is the expiry yars token add stores (RFC 3339, "" for
// never): --days N from now (the default, tokenDays; 0 is never), or
// --expires, a day (YYYY-MM-DD, to its end in UTC) or never. Both flags
// together, a day that is past and one that does not read are refused.
func tokenExpiry(days int, expires string, daysGiven, expiresGiven bool, now time.Time) (string, error) {
	switch {
	case daysGiven && expiresGiven:
		return "", errors.New("give --days or --expires, not both")
	case expiresGiven && expires == "never":
		return "", nil
	case expiresGiven:
		day, err := time.Parse("2006-01-02", expires)
		if err != nil {
			return "", fmt.Errorf("--expires: %q is not a date (YYYY-MM-DD) or never", expires)
		}
		end := day.Add(24*time.Hour - time.Second)
		if end.Before(now) {
			return "", fmt.Errorf("--expires: %s is in the past", expires)
		}
		return end.Format(time.RFC3339), nil
	case days < 0:
		return "", errors.New("--days: 0 or more (0 = never)")
	case days == 0:
		return "", nil
	}
	return now.Add(time.Duration(days) * 24 * time.Hour).Format(time.RFC3339), nil
}

// splitList splits a comma-separated flag value (empty items dropped).
func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// writeIgnore adds the server-only lines to .gitignore; it reports whether
// the file changed.
func writeIgnore(dir string) (bool, error) {
	gi := filepath.Join(dir, ".gitignore")
	b, _ := os.ReadFile(gi)
	next := string(b)
	// an older YARS's comment over the same lines gives way to the current one
	current, _, _ := strings.Cut(serverIgnore, "\n")
	for _, old := range oldIgnoreComments {
		if strings.Contains(next, old+"\n") && !strings.Contains(next, current+"\n") {
			next = strings.Replace(next, old+"\n", current+"\n", 1)
		}
	}
	for _, l := range strings.Split(strings.TrimSpace(serverIgnore), "\n") {
		if !strings.Contains(next, l) {
			if next != "" && !strings.HasSuffix(next, "\n") {
				next += "\n"
			}
			next += l + "\n"
		}
	}
	if next == string(b) {
		return false, nil
	}
	return true, os.WriteFile(gi, []byte(next), 0o600)
}

// ensureIgnored makes sure server-only files are ignored and not tracked,
// so a clone never carries password hashes, tokens or the database (older
// repos committed users.yaml; their history still does — rewrite it if that
// matters).
func ensureIgnored(r *gitrepo.Repo) error {
	if changed, err := writeIgnore(r.Dir); err != nil {
		return err
	} else if changed {
		if err := r.Commit([]string{".gitignore"}, "ignore server-only files (accounts, tokens, database)", system); err != nil {
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

// engOfGitDir returns the engagement whose repository gitDir belongs to
// (<data>/engagements/<id>/.git), or "" for the main repo.
func engOfGitDir(dataDir, gitDir string) string {
	if gitDir == "" {
		return ""
	}
	// compare physical paths: git gives the hook a symlink-free GIT_DIR
	if p, err := filepath.EvalSymlinks(dataDir); err == nil {
		dataDir = p
	}
	if p, err := filepath.EvalSymlinks(gitDir); err == nil {
		gitDir = p
	}
	rel, err := filepath.Rel(filepath.Join(dataDir, "engagements"), gitDir)
	if err != nil {
		return ""
	}
	seg := strings.Split(filepath.ToSlash(rel), "/")
	if len(seg) == 2 && seg[1] == ".git" && store.ValidID(seg[0]) {
		return seg[0]
	}
	return ""
}

// objectID reports whether s is a git object name: 40 hex digits (SHA-1)
// or 64 (SHA-256), lower case as git writes them.
func objectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	return strings.Trim(s, "0123456789abcdef") == ""
}

// cmdHook implements "yars hook pre-receive": reads "<old> <new> <ref>"
// lines from git, checks them against the server's rules and prints one
// "yars: <problem>" line per rejection reason. Exit 1 rejects the push.
func cmdHook(args []string, in io.Reader, errOut io.Writer) int {
	if len(args) == 0 || args[0] != "pre-receive" {
		fmt.Fprintln(errOut, "yars: usage: yars hook pre-receive --data <dir> | yars hook install [--data <clone>]")
		return 2
	}
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	data := fs.String("data", ".", "data repo")
	engFlag := fs.String("eng", "", "the engagement whose repository is pushed (set in its hook)")
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
	// a config that does not load leaves only its repair open (ConfigErr)
	cfg, cfgErr := config.Load(r.Dir)
	if cfgErr != nil {
		cfg = config.Default()
	}
	d, err := dataDB(r.Dir)
	if err != nil {
		return fail(err.Error())
	}
	defer d.Close()
	// the workflow is the one yars init set up, as the database records it:
	// the running server keeps it (store.applyConfig), whatever config.yaml
	// says now (broken, so the defaults, or changed by a hand edit), and a
	// push is held to it
	simple, err := simpleData(d)
	if err != nil {
		return fail(err.Error())
	}
	cfg.Workflow = ""
	if simple {
		cfg.Workflow = config.WorkflowSimple
	}
	users, err := d.Users()
	if err != nil {
		return fail(err.Error())
	}
	// every line is "<old> <new> <ref>": anything else, or input that cannot
	// be read whole, refuses the push (a skipped line's update would land
	// unchecked)
	var ups []policy.Update
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 || !objectID(f[0]) || !objectID(f[1]) {
			return fail(fmt.Sprintf("unreadable hook input %.80q; push refused", sc.Text()))
		}
		ups = append(ups, policy.Update{Old: f[0], New: f[1], Ref: f[2]})
	}
	if err := sc.Err(); err != nil {
		return fail("unreadable hook input (" + err.Error() + "); push refused")
	}
	// which repository is being pushed to: the main repo or engagements/<id>
	c := &policy.Checker{Repo: r, Cfg: cfg, Users: users, DB: d, ConfigErr: cfgErr}
	c.Token = policy.TokenFromEnv(os.LookupEnv(policy.TokenScopesEnv))
	eng := *engFlag
	if eng == "" {
		eng = engOfGitDir(r.Dir, os.Getenv("GIT_DIR"))
	}
	if eng != "" && !store.ValidID(eng) {
		return fail("bad engagement " + eng)
	}
	if eng != "" {
		er, err := gitrepo.Open(filepath.Join(r.Dir, "engagements", eng))
		if err != nil {
			return fail(err.Error())
		}
		c.Repo, c.Eng = er, eng
	}
	// the server's own rules, as the Check button runs them (AI rules
	// excepted: they wait on the provider for up to a minute and a half)
	re := rules.NewEngine(rules.DirFor(r.Dir), cfg)
	re.Runner = pushRunner{re.Runner}
	c.Linter = re
	ps := c.Check(user, ups)
	for _, n := range c.Notes {
		fmt.Fprintln(errOut, "yars: "+n)
	}
	for _, p := range ps {
		fmt.Fprintln(errOut, "yars: "+p)
	}
	if len(ps) > 0 {
		return 1
	}
	// a director's edit keeps an approved finding approved: the server
	// moves the approval once the push lands (store.ReceivePush)
	return 0
}

// pushRunner runs script rules on a push as the Check button does, and
// reports AI rules as not run.
type pushRunner struct{ rules.SlowRunner }

func (p pushRunner) AI(_ context.Context, r rules.Rule, _, _ string) []rules.Violation {
	return []rules.Violation{{Rule: r.ID, Level: "warning", Target: "ai", Message: "AI rules run with Check on the finding page, not on push"}}
}

// cmdLint checks findings against the style rules. Exit code 1 when any
// error-level violation is found. With --staged it asks the clone's server
// to check the findings staged for a commit instead (the pre-commit hook);
// the exit code is then notChecked (3) when the server could not be asked,
// and always 0 with --warn-only.
func cmdLint(args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	data := dataFlag(fs)
	fs.Bool("fast", true, "only regex and built-in rules (the default)")
	all := fs.Bool("all", false, "also run script and AI rules (runs code from the repo and sends text to the AI provider)")
	staged := fs.Bool("staged", false, "ask the server to check the findings staged in the engagement clone in the current folder (or --data)")
	warnOnly := fs.Bool("warn-only", false, "with --staged: always exit 0")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if fs.NArg() > 1 { // the flag package stops at the scope: never ignore what follows
		if strings.HasPrefix(fs.Arg(1), "-") {
			return 2, fmt.Errorf("usage: yars lint [flags] [<engagement>[/<finding>]]: flags go before the scope; %q is after it", fs.Arg(1))
		}
		return 2, fmt.Errorf("usage: yars lint [flags] [<engagement>[/<finding>]]: one scope only; %q is a second", fs.Arg(1))
	}
	if *staged && fs.NArg() > 0 {
		return 2, fmt.Errorf("usage: yars lint --staged [--warn-only]: it checks what is staged, so it takes no scope (%q)", fs.Arg(0))
	}
	if *staged {
		dir := *data
		if dir == "" {
			dir = "."
		}
		ctx, cancel := context.WithTimeout(context.Background(), lintTimeout)
		defer cancel()
		errs, _, checked, err := lintStagedChecked(ctx, dir, out, *warnOnly)
		switch {
		case *warnOnly:
			if err != nil {
				fmt.Fprintln(out, "yars:", err)
			}
			return 0, nil
		case err != nil:
			return 2, err
		case !checked:
			return notChecked, nil
		case errs > 0:
			return 1, nil
		}
		return 0, nil
	}
	r, err := openData(fs, *data)
	if err != nil {
		return 2, err
	}
	cfg, err := config.Load(r.Dir)
	if err != nil {
		return 2, err
	}
	d, err := existingDB(r.Dir)
	if err != nil {
		return 2, err
	}
	if d != nil {
		defer d.Close()
	}
	st := store.New(r, cfg, d)
	st.Logger = termLogger()
	eng := rules.NewEngine(rules.DirFor(r.Dir), cfg)
	eng.SetLogger(st.Logger)
	if rn, ok := eng.Runner.(*rules.Runner); ok && d != nil {
		// on the data folder the AI rules use what Admin › AI saved, as the
		// server does (a clone has no database: config.yaml alone). The key
		// is read with the folder's key file only when there is one: this
		// command makes none.
		rn.Stored = func() (config.AIConfig, string) {
			return d.AIStored(func() (*secret.Box, error) {
				if _, err := os.Stat(secret.KeyPath(r.Dir)); err != nil {
					return nil, err
				}
				return secret.Open(r.Dir)
			})
		}
	}
	kinds := rules.Fast
	if *all {
		kinds = rules.All
	}
	scopeEng, scopeDir, _ := strings.Cut(fs.Arg(0), "/")
	engs, err := st.ListEngagements()
	if err != nil {
		return 2, err
	}
	code, checked, matched := 0, 0, false
	// the rules' own load problems once, before the findings (each finding's
	// result repeats them: skipped below; a rule that fails to run on a
	// finding is that finding's)
	problems := eng.Rules().Problems
	for _, p := range problems {
		fmt.Fprintf(out, "rules %s %s: %s\n", p.Level, p.Rule, p.Message)
		if p.Level == "error" {
			code = 1
		}
	}
	for _, e := range engs {
		if scopeEng != "" && e.ID != scopeEng {
			continue
		}
		var refs []store.FindingRef
		if scopeDir != "" {
			// named as the website names it: folder, ID or number
			ref, err := st.Finding(e.ID, scopeDir)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return 2, err
			}
			if err == nil {
				refs, matched = append(refs, ref), true
			}
		} else if refs, err = st.ListFindings(e.ID); err != nil {
			return 2, err
		} else {
			matched = true // the engagement, even with no findings yet
		}
		for _, ref := range refs {
			checked++
			// what was dismissed on the finding page is left out, as in the
			// server's answer to the pre-commit check (a clone has no
			// database and no dismissals)
			var dismissed map[string]db.Dismissal
			if d != nil {
				if dismissed, err = st.Dismissals(e.ID, ref.F.Meta.ID); err != nil {
					return 2, err
				}
			}
			for _, v := range eng.Lint(context.Background(), ref.F, kinds) {
				if v.Target == "rules" && slices.Contains(problems, v) {
					continue // printed once above
				}
				if _, ok := db.Lookup(dismissed, v.Rule, v.Target, v.Quote); ok {
					continue
				}
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
	if !matched && fs.Arg(0) != "" {
		return 2, fmt.Errorf("no finding matches %s", fs.Arg(0))
	}
	fmt.Fprintf(out, "%d finding(s) checked\n", checked)
	return code, nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage (flags first; --data defaults to $YARS_DATA, then yars use, then .):
  yars version
  yars init [--simple] <dir>   (--simple: draft → complete → reported, no roles; fixed after init)
  yars use [<dir>]   (set the default data folder, or show it)
  yars serve --data <dir> [--addr :8080] [--tls-cert <file> --tls-key <file>] [--https] [--log-level debug|info|warn|error]
  yars status --data <dir>   (what the running server does now; run it as the server's account)
  yars useradd --data <dir> --role pentester|reviewer|director [--email e] [--admin] <user>   (no --role in the simple workflow)
  yars admin --data <dir> <user> on|off
  yars passwd --data <dir> <user>
      (useradd, passwd: the password is asked twice on a terminal; a piped one must be changed at the next login)
  yars role --data <dir> <user> pentester|reviewer|director   (not in the simple workflow)
  yars userdel --data <dir> <user>
  yars unlock --data <dir> <user>   (end a login lockout)
  yars token add --data <dir> [--kind mcp|git] [--scopes all|read|a,b] [--engagements e1,e2] [--days N | --expires YYYY-MM-DD|never] [--name n] <user>   (90 days without either; --days 0 = never)
  yars token list --data <dir>
  yars token revoke --data <dir> [--id N] <user>
  yars migrate --data <dir>
  yars backup --data <dir> [--key] --out <file.zip>
  yars restore --from <file.zip> --data <new dir>
  yars lint --data <dir> [--all] [eng[/finding]]
  yars lint --staged [--warn-only] [--data <engagement clone>]   (the server checks what is being committed; exit 1: errors, 3: not checked)
  yars hook install [--data <clone>]   (a pre-commit hook in every engagement of the clone)
  yars export --data <dir> --exporter <id> [--out <file>] [--force] <eng> [<finding>…]   (--force: replace the file)
  yars mcp --data <clone> --user <name>
  yars seed [--simple] --data <new dir> [--engagements 2] [--findings 20] [--messages 50]   (development data; prints the accounts' password)`)
	os.Exit(2)
}

// serverSide reports whether a command (args: its name and what follows)
// works on the server's data folder, where everything it and its git child
// processes write is the service user's alone (privateUmask). The commands
// of a user's own clone (mcp, lint, hook install, use) keep the user's umask.
func serverSide(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "hook":
		return len(args) > 1 && args[1] == "pre-receive"
	case "init", "serve", "useradd", "passwd", "role", "userdel", "admin", "unlock", "token",
		"migrate", "backup", "restore", "seed", "export":
		return true
	}
	return false
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	if serverSide(os.Args[1:]) {
		privateUmask()
	}
	var err error
	switch os.Args[1] {
	case "version":
		err = cmdVersion(os.Args[2:], os.Stdout)
	case "init":
		err = cmdInit(os.Args[2:])
	case "useradd":
		err = cmdUseradd(os.Args[2:], os.Stdin, os.Stderr)
	case "passwd":
		err = cmdPasswd(os.Args[2:], os.Stdin, os.Stderr)
	case "role":
		err = cmdRole(os.Args[2:], os.Stderr)
	case "userdel":
		err = cmdUserdel(os.Args[2:], os.Stderr)
	case "admin":
		err = cmdAdmin(os.Args[2:], os.Stderr)
	case "unlock":
		err = cmdUnlock(os.Args[2:], os.Stdout)
	case "use":
		err = cmdUse(os.Args[2:], os.Stdout)
	case "migrate":
		err = cmdMigrate(os.Args[2:], os.Stdout)
	case "backup":
		err = cmdBackup(os.Args[2:], os.Stdout)
	case "restore":
		err = cmdRestore(os.Args[2:], os.Stdout)
	case "serve":
		err = cmdServe(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:], os.Stdout)
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
		if len(os.Args) > 2 && os.Args[2] == "install" {
			err = cmdHookInstall(os.Args[3:], os.Stdout)
			break
		}
		os.Exit(cmdHook(os.Args[2:], os.Stdin, os.Stderr))
	case "seed":
		err = cmdSeed(os.Args[2:], os.Stdout)
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

func cmdInit(args []string) error { return cmdInitOut(args, os.Stdout) }

// cmdInitOut sets up a data folder: yars init [--simple] <dir>. The
// workflow is chosen here and fixed after it.
func cmdInitOut(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	simple := fs.Bool("simple", false, "the simple workflow: draft → complete → reported, no roles or reviewers")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 && strings.HasPrefix(fs.Arg(1), "-") { // the flag package stops at the folder
		return fmt.Errorf("usage: yars init [--simple] <dir>: flags go before the folder; %q is after it", fs.Arg(1))
	}
	if fs.NArg() != 1 {
		usage()
	}
	if err := initDataMode(fs.Arg(0), *simple); err != nil {
		return err
	}
	if *simple {
		fmt.Fprintln(out, "initialised", fs.Arg(0), "(simple workflow)")
	} else {
		fmt.Fprintln(out, "initialised", fs.Arg(0))
	}
	return nil
}

// cmdSeed builds a fresh data directory with generated data (development
// and benchmarks): yars seed [--simple] --data <dir> [--engagements N]
// [--findings M] [--messages K]. Without the numbers it is small (2
// engagements of 20 findings, 50 messages). The accounts share one random
// password, printed once.
func cmdSeed(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	data := fs.String("data", "", "new data directory (must not exist or be empty)")
	o := seed.Options{}
	fs.IntVar(&o.Engagements, "engagements", 2, "engagements")
	fs.IntVar(&o.Findings, "findings", 20, "findings per engagement")
	fs.IntVar(&o.Messages, "messages", 50, "chat messages in all")
	fs.BoolVar(&o.Simple, "simple", false, "a data folder of the simple workflow (yars init --simple)")
	fs.SetOutput(out)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *data == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: yars seed [--simple] --data <dir> [--engagements N] [--findings M] [--messages K]")
	}
	if ents, err := os.ReadDir(*data); err == nil && len(ents) > 0 {
		return fmt.Errorf("%s is not empty", *data)
	}
	start := time.Now()
	if err := initDataMode(*data, o.Simple); err != nil {
		return err
	}
	// the accounts get a random password, printed here once
	pw, err := seed.Fill(*data, o)
	if err != nil {
		return err
	}
	users := seed.Users
	if o.Simple {
		users = seed.SimpleUsers
	}
	var names []string
	for _, u := range users {
		names = append(names, u.Username)
	}
	fmt.Fprintf(out, "seeded %s: %d engagements × %d findings, %d messages in %s; users %s (password %s)\n",
		*data, o.Engagements, o.Findings, o.Messages, time.Since(start).Round(time.Millisecond), strings.Join(names, ", "), pw)
	return nil
}

// workflowSetting is the database setting yars init --simple writes, and a
// new database takes from config.yaml (dataDB) (config.WorkflowSimple; unset
// for the standard workflow): the workflow the data folder was set up with,
// which config.yaml's workflow key must keep.
const workflowSetting = "workflow"

// initData creates and initialises a data directory with the standard
// workflow (initDataMode).
func initData(dir string) error { return initDataMode(dir, false) }

// initDataMode creates and initialises a data directory: main repo, config,
// example exporters, database. It writes no rules: the owner adds the ones
// they want (Admin › Rules, or files in .yars/rules/). With simple it sets
// up the simple workflow: config.yaml's workflow key and the database's
// workflow setting (the standard workflow writes neither).
func initDataMode(dir string, simple bool) error {
	r, err := gitrepo.Init(dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(config.ConfigPath(dir)); err == nil {
		return fmt.Errorf("%s is already initialised", dir)
	}
	// folders 0700 and files 0600: the data is the service user's alone
	if err := os.MkdirAll(filepath.Join(dir, "engagements"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(config.ConfigPath(dir)), 0o700); err != nil {
		return err
	}
	cfg := config.Default()
	if simple {
		cfg.Workflow = config.WorkflowSimple
	}
	b, _ := yaml.Marshal(cfg)
	files := map[string][]byte{
		config.ConfigPath(dir):                        b,
		filepath.Join(dir, ".gitignore"):              []byte(serverIgnore),
		filepath.Join(dir, "engagements", ".gitkeep"): nil,
	}
	for p, c := range files {
		if err := os.WriteFile(p, c, 0o600); err != nil {
			return err
		}
	}
	exDir := filepath.Join(dir, ".yars", "exporters")
	if err := os.MkdirAll(exDir, 0o700); err != nil {
		return err
	}
	for name, body := range exampleExporters {
		if err := os.WriteFile(filepath.Join(exDir, name), []byte(body), 0o600); err != nil {
			return err
		}
	}
	// the database (accounts, workflow state, chat) stays on the server only
	d, err := dataDB(dir)
	if err != nil {
		return err
	}
	if simple {
		if err := d.SetSetting(workflowSetting, config.WorkflowSimple); err != nil {
			d.Close()
			return err
		}
	}
	d.Close()
	// the key that encrypts personal and AI keys in the database (git-ignored)
	if err := secret.EnsureKey(dir); err != nil {
		return err
	}
	return r.Commit([]string{".yars/config.yaml", ".yars/exporters", ".gitignore", "engagements"}, "init", system)
}

// accountCmd parses "--data <dir> <args…>" (want positional arguments) and
// opens the data directory's database.
func accountCmd(name string, args []string, want int, setup func(*flag.FlagSet)) (*flag.FlagSet, *db.DB, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	data := dataFlag(fs)
	if setup != nil {
		setup(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}
	if fs.NArg() != want {
		return nil, nil, fmt.Errorf("wrong arguments; see yars help")
	}
	r, err := openData(fs, *data)
	if err != nil {
		return nil, nil, err
	}
	if err := ensureIgnored(r); err != nil {
		return nil, nil, err
	}
	d, err := dataDB(r.Dir)
	return fs, d, err
}

// errNoRoles refuses a role in the simple workflow, where every account is
// stored as a director and only the admin flag tells accounts apart.
var errNoRoles = errors.New("the simple workflow has no roles")

// simpleRole is an account's role in the simple workflow: director, with
// --role director or without --role (given: whether it was set); any other
// role is refused.
func simpleRole(given bool, role string) (string, error) {
	if given && role != "director" {
		return "", errNoRoles
	}
	return "director", nil
}

// flagGiven reports whether the command line set the flag name.
func flagGiven(fs *flag.FlagSet, name string) bool {
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == name })
	return given
}

// simpleData reports whether the data folder was set up with the simple
// workflow, as its database records it (workflowSetting).
func simpleData(d *db.DB) (bool, error) {
	w, err := d.Setting(workflowSetting)
	return w == config.WorkflowSimple, err
}

// hiddenLine reads a line from a terminal without showing it; typed is
// false when in is no terminal (a test replaces it).
var hiddenLine = termLine

// readPassword reads the new password of useradd and passwd and returns its
// hash. On a terminal it is typed twice and not shown (typed true). Piped,
// it is the first line of in: such a password passed through a shell line
// or a script, so the caller makes the account set a new one.
func readPassword(in io.Reader, out io.Writer) (hash string, typed bool, err error) {
	fmt.Fprint(out, "password: ")
	pw, typed, err := hiddenLine(in)
	if err != nil {
		return "", typed, err
	}
	if !typed {
		line, rerr := bufio.NewReader(in).ReadString('\n')
		if pw = strings.TrimRight(line, "\r\n"); pw == "" {
			return "", false, fmt.Errorf("empty password (%v)", rerr)
		}
	} else if pw == "" {
		return "", true, errors.New("empty password")
	}
	if p := auth.PasswordProblem(pw); p != "" { // as the website asks
		return "", typed, errors.New("password: " + p)
	}
	if typed {
		fmt.Fprint(out, "\nrepeat password: ")
		again, _, err := hiddenLine(in)
		if err != nil {
			return "", true, err
		}
		if again != pw {
			return "", true, errors.New("the two passwords differ")
		}
	}
	hash, err = auth.HashPassword(pw)
	return hash, typed, err
}

func cmdUseradd(args []string, in io.Reader, out io.Writer) error {
	var role, email *string
	var admin *bool
	fs, d, err := accountCmd("useradd", args, 1, func(fs *flag.FlagSet) {
		role = fs.String("role", "pentester", "pentester|reviewer|director")
		email = fs.String("email", "", "email for git authorship")
		admin = fs.Bool("admin", false, "may open the admin pages")
	})
	if err != nil {
		return err
	}
	defer d.Close()
	name := fs.Arg(0)
	simple, err := simpleData(d)
	if err != nil {
		return err
	}
	if simple {
		if *role, err = simpleRole(flagGiven(fs, "role"), *role); err != nil {
			return err
		}
	}
	if !config.ValidRole(*role) {
		return fmt.Errorf("invalid role %q (want %s)", *role, strings.Join(config.Roles, ", "))
	}
	if !store.ValidID(name) {
		return fmt.Errorf("invalid username %q", name)
	}
	if _, ok, _ := d.User(name); ok {
		return fmt.Errorf("user %s already exists", name)
	}
	hash, typed, err := readPassword(in, out)
	if err != nil {
		return err
	}
	// a piped password is a temporary one, the first admin's too
	if err := d.AddUser(config.User{Username: name, Email: *email, Role: *role, PasswordHash: hash, IsAdmin: *admin, MustChange: !typed}); err != nil {
		return err
	}
	detail := "role " + *role
	if *admin {
		detail += ", admin"
	}
	if simple { // no roles to name: the admin flag only
		detail = ""
		if *admin {
			detail = "admin"
		}
	}
	d.Audit("cli", "user.add", name, detail)
	switch {
	case simple && *admin:
		fmt.Fprintln(out, "\nadded", name, "(admin)")
	case simple:
		fmt.Fprintln(out, "\nadded", name)
	case *admin:
		fmt.Fprintln(out, "\nadded", name, "as", *role, "(admin)")
	default:
		fmt.Fprintln(out, "\nadded", name, "as", *role)
	}
	if !typed {
		fmt.Fprintln(out, "the first login asks for a new password")
	}
	return nil
}

// cmdAdmin turns the admin flag on or off: yars admin --data <dir> <user> on|off
func cmdAdmin(args []string, out io.Writer) error {
	fs, d, err := accountCmd("admin", args, 2, nil)
	if err != nil {
		return err
	}
	defer d.Close()
	on := fs.Arg(1) == "on"
	if !on && fs.Arg(1) != "off" {
		return fmt.Errorf("usage: yars admin --data <dir> <user> on|off")
	}
	if err := d.SetAdmin(fs.Arg(0), on); err != nil {
		return err
	}
	d.Audit("cli", "user.admin", fs.Arg(0), fs.Arg(1))
	fmt.Fprintln(out, fs.Arg(0), "admin", fs.Arg(1))
	return nil
}

func cmdPasswd(args []string, in io.Reader, out io.Writer) error {
	fs, d, err := accountCmd("passwd", args, 1, nil)
	if err != nil {
		return err
	}
	defer d.Close()
	if _, ok, _ := d.User(fs.Arg(0)); !ok {
		return fmt.Errorf("no user %s", fs.Arg(0))
	}
	hash, typed, err := readPassword(in, out)
	if err != nil {
		return err
	}
	// a piped password is a temporary one (ResetPassword); one typed here
	// leaves the account's need for a new password as it was
	set := d.ResetPassword
	if typed {
		set = d.SetPassword
	}
	if err := set(fs.Arg(0), hash); err != nil {
		return err
	}
	d.Audit("cli", "user.password", fs.Arg(0), "")
	fmt.Fprintln(out, "\npassword changed for", fs.Arg(0))
	if !typed {
		fmt.Fprintln(out, "the next login asks for a new password")
	}
	return nil
}

func cmdRole(args []string, out io.Writer) error {
	fs, d, err := accountCmd("role", args, 2, nil)
	if err != nil {
		return err
	}
	defer d.Close()
	if simple, err := simpleData(d); err != nil {
		return err
	} else if simple {
		return errNoRoles
	}
	if err := d.SetRole(fs.Arg(0), fs.Arg(1)); err != nil {
		return err
	}
	d.Audit("cli", "user.role", fs.Arg(0), fs.Arg(1))
	fmt.Fprintln(out, fs.Arg(0), "is now", fs.Arg(1))
	return nil
}

func cmdUserdel(args []string, out io.Writer) error {
	fs, d, err := accountCmd("userdel", args, 1, nil)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.DeleteUser(fs.Arg(0)); err != nil {
		return err
	}
	d.Audit("cli", "user.delete", fs.Arg(0), "")
	fmt.Fprintln(out, "deleted", fs.Arg(0), "(their sessions and API tokens too)")
	return nil
}
