package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/events"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/gitserve"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/secret"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/web"
	"github.com/abno525/yars/internal/workflow"
)

// stopGrace is how long a stop waits for requests in flight, and then for
// running checks.
const stopGrace = 30 * time.Second

// backfillTeams runs the one-time team backfill against the engagements on
// disk (db.BackfillTeams).
func backfillTeams(st *store.Store, d *db.DB) error {
	engs, err := st.ListEngagements()
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(engs))
	for _, e := range engs {
		ids = append(ids, e.ID)
	}
	return d.BackfillTeams(ids)
}

// startConfig is the first step of every start: a push cut off mid-way
// leaves no tree behind, then config.yaml is loaded (and checked). The
// service log is built from it (serverLog), so nothing is logged before.
func startConfig(r *gitrepo.Repo) (config.Config, error) {
	if err := gitserve.RestoreTrees(r); err != nil {
		return config.Config{}, fmt.Errorf("restore work trees: %w", err)
	}
	return config.Load(r.Dir)
}

// serverLog is the service log of yars serve on w (stderr): config.yaml's
// log.format, and its log.level unless --log-level (flagLevel, "" = not
// given) names another. Both were checked before. The level sits in a
// slog.LevelVar, so it can change while the server runs.
func serverLog(w io.Writer, cfg config.Config, flagLevel string) (*slog.Logger, *slog.LevelVar) {
	lg, lv, _ := serverLogRing(w, cfg, flagLevel)
	return lg, lv
}

// serverLogRing is serverLog with the ring that keeps the log's last warn
// and error lines in memory (Admin › System, yars status): behind the same
// redaction as w, and at its own level whatever log.level is.
func serverLogRing(w io.Writer, cfg config.Config, flagLevel string) (*slog.Logger, *slog.LevelVar, *logs.Ring) {
	word := cfg.Log.Level
	if flagLevel != "" {
		word = flagLevel
	}
	lv := new(slog.LevelVar)
	level, _ := logs.ParseLevel(word)
	lv.Set(level)
	ring := logs.NewRing()
	return slog.New(logs.HandlerRing(w, cfg.Log.Format, lv, ring)), lv, ring
}

// prepareData readies a data folder the way every start does, after
// startConfig and before the first request: files a stop left uncommitted
// in the findings folders are removed, the database is opened (and
// migrated), config.yaml's workflow is checked against the one yars init
// set up, teams are backfilled, board claims a stop cut off are reset,
// server files are git-ignored and the engagement pointers follow their
// repositories. The store logs to lg. The upgrade test runs it on old data.
func prepareData(r *gitrepo.Repo, cfg config.Config, lg *slog.Logger) (*db.DB, *store.Store, error) {
	if items := legacyItems(r.Dir); len(items) > 0 {
		return nil, nil, fmt.Errorf("this data directory still keeps accounts, workflow state or chat in files (%s); run: yars migrate --data %s", strings.Join(items, ", "), r.Dir)
	}
	cleanLeftovers(r, lg)
	d, err := dataDB(r.Dir)
	if err != nil {
		return nil, nil, err
	}
	if err := checkWorkflow(cfg, d); err != nil {
		d.Close()
		return nil, nil, err
	}
	// accounts from before such names were refused: both keep working
	if clashes, err := d.UsernameClashes(); err == nil {
		for _, c := range clashes {
			logs.Or(lg).Warn("accounts whose usernames differ only in the case of letters", "users", c)
		}
	}
	st := store.New(r, cfg, d)
	st.Logger = lg
	fail := func(what string, err error) (*db.DB, *store.Store, error) {
		d.Close()
		return nil, nil, fmt.Errorf("%s: %w", what, err)
	}
	if err := backfillTeams(st, d); err != nil {
		return fail("team backfill", err)
	}
	// a Make finding claim now is one a stop cut off
	if err := d.ResetBoardClaims(); err != nil {
		return fail("team board", err)
	}
	if err := ensureIgnored(r); err != nil {
		return fail("ignore server files", err)
	}
	if err := st.SyncPointers(); err != nil {
		return fail("update engagement pointers", err)
	}
	return d, st, nil
}

// cleanLeftovers removes what a stop between a write and its commit left
// in the engagements' findings folders (gitserve.CleanLeftovers), before
// anything reads them, and logs a line per engagement: its ID and a count,
// never a name. While another server answers on the data folder (a second
// yars serve started by mistake) nothing is removed: that server's files
// between write and commit look the same. A failure is logged and the start
// goes on.
func cleanLeftovers(r *gitrepo.Repo, lg *slog.Logger) {
	if otherServer(r.Dir) {
		logs.Or(lg).Warn("start: another server runs on this data folder; uncommitted files in the findings folders are left")
		return
	}
	cleaned, err := gitserve.CleanLeftovers(r)
	for _, c := range cleaned {
		logs.Or(lg).Warn("start: uncommitted files were removed from an engagement's findings folder", "eng", c.Eng, "count", c.N)
	}
	if err != nil {
		logs.Or(lg).Error("start: uncommitted files are not removed", "err", err)
	}
}

// checkWorkflow refuses a config.yaml whose workflow is not the one the
// data folder was set up with: yars init records it in the database
// (workflowSetting), and it cannot change after (a hand edit of the file).
func checkWorkflow(cfg config.Config, d *db.DB) error {
	set, err := d.Setting(workflowSetting)
	if err != nil {
		return fmt.Errorf("workflow setting: %w", err)
	}
	if set == "" {
		set = config.WorkflowStandard
	}
	if now := workflow.FlowOf(cfg).Name(); now != set {
		return fmt.Errorf("config.yaml says workflow %s but this data folder was set up with %s (yars init); put workflow: %s back", now, set, set)
	}
	return nil
}

// firstRunCode is the setup code of a start that finds no account: /setup
// asks for it before it makes the first admin, so whoever reaches the port
// first cannot take the server. It is logged once (setup_code), with the way
// to make the admin from the shell instead (no code there), and kept in
// memory only. The line is written whatever log.level says: without it
// /setup cannot be used. A start that finds an account (or cannot read them)
// makes none: "" keeps /setup closed, also when every account is deleted
// while the server runs.
func firstRunCode(d *db.DB, cfg config.Config, dir string, lg *slog.Logger) string {
	if users, err := d.Users(); err != nil || len(users) > 0 {
		return ""
	}
	role := "--role director " // the simple workflow has no roles
	if cfg.Simple() {
		role = ""
	}
	code := web.NewSetupCode()
	logs.Or(lg).Log(context.Background(), logs.Always, "no accounts yet: open the web page and set up the first admin with the setup code (/setup), or run the command",
		"setup_code", code, "command", "yars useradd --data "+dir+" "+role+"--admin <name>")
	return code
}

// warnNoBaseURL logs, at the start, that config.yaml sets no base_url: the
// clone and MCP addresses on the pages then take their host from each
// request, which a client chooses.
func warnNoBaseURL(cfg config.Config, lg *slog.Logger) {
	if cfg.BaseURL == "" {
		logs.Or(lg).Warn("base_url is not set in .yars/config.yaml: the clone and MCP addresses shown on the pages take their host from each request's Host header; set base_url to the address people open")
		if cfg.SMTP.Configured() {
			// a mail's link would be a bare path
			logs.Or(lg).Warn("smtp is set but base_url is not: no notification email is sent until base_url is set")
		}
	}
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	data := dataFlag(fs)
	addr := fs.String("addr", ":8080", "listen address")
	cert := fs.String("tls-cert", "", "serve HTTPS with this certificate file (needs --tls-key)")
	key := fs.String("tls-key", "", "the certificate's private key file (needs --tls-cert)")
	https := fs.Bool("https", false, "a proxy in front serves HTTPS: Secure cookies and HSTS")
	logLevel := fs.String("log-level", "", "log lines from this level up: debug, info, warn or error (default: log.level in config.yaml, else info)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*cert == "") != (*key == "") {
		return fmt.Errorf("--tls-cert and --tls-key go together")
	}
	// a level that is no level stops the start before anything changes
	if _, ok := logs.ParseLevel(*logLevel); !ok {
		return fmt.Errorf("--log-level %q must be debug, info, warn or error", *logLevel)
	}
	secure := *https || *cert != ""
	// a certificate that does not load stops the start before anything changes
	var tlsCfg *tls.Config
	if *cert != "" {
		pair, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			return fmt.Errorf("--tls-cert, --tls-key: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	}
	// a git that is missing or too old stops the start before anything
	// changes: with an old one the server would run and refuse every push
	gitUnread, err := checkGit()
	if err != nil {
		return err
	}
	r, err := openData(fs, *data)
	if err != nil {
		return err
	}
	cfg, err := startConfig(r)
	if err != nil {
		return err
	}
	lg, level, ring := serverLogRing(os.Stderr, cfg, *logLevel)
	if gitUnread {
		logGitUnread(lg)
	}
	d, st, err := prepareData(r, cfg, lg)
	if err != nil {
		return err
	}
	warnNoBaseURL(cfg, lg)
	setupCode := firstRunCode(d, cfg, r.Dir, lg)
	exe, err := os.Executable()
	if err != nil {
		d.Close()
		return err
	}
	srv, err := serverParts(r, cfg, d, st, lg, exe, secure, setupCode)
	if err != nil {
		d.Close()
		return err
	}
	// the log's ring and its level are the server's to show and to switch
	// (Admin › System: the last lines, debug for 15 minutes)
	srv.LogRing, srv.LogLevel = ring, level
	hs := srv.HTTPServer(*addr)
	hs.TLSConfig = tlsCfg
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	// yars status reads this server on a socket in the data folder; it is
	// opened once the address is this server's, and closed when it stops
	defer startStatus(r.Dir, srv, lg)()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// after the first signal a second one ends the process at once (a stop
	// can take up to twice stopGrace)
	context.AfterFunc(ctx, stop)
	logStart(lg, srv, cfg, r.Dir, *addr, secure)
	return serve(ctx, ln, hs, srv, st, d)
}

// logStart writes the line of a start, once the server is built: the
// version, the schema, the workflow, the address it listens on and whether
// it serves HTTPS, the data folder, and which optional parts are on: AI (a
// provider and a key are set), SMTP and pandoc. Each of the three is yes or
// no: never a key, a variable's name, a host or a login.
func logStart(lg *slog.Logger, srv *web.Server, cfg config.Config, dir, addr string, secure bool) {
	ai := srv.Rules != nil && srv.Rules.AIConfigured()
	pandoc := srv.Export != nil && srv.Export.PandocPath != ""
	logs.Or(lg).Info("yars serving", "version", buildVersion(), "schema", db.SchemaVersion, "workflow", workflow.FlowOf(cfg).Name(),
		"addr", addr, "https", secure, "data", dir, "ai", ai, "smtp", cfg.MailOn(), "pandoc", pandoc)
}

// serverParts builds the server on prepared data: the rules, the accounts,
// the git and MCP endpoints and the website, each logging to lg (the store
// got it in prepareData). exe is the yars binary the push hook runs; secure:
// the site is served over HTTPS; setupCode: firstRunCode's.
func serverParts(r *gitrepo.Repo, cfg config.Config, d *db.DB, st *store.Store, lg *slog.Logger, exe string, secure bool, setupCode string) (*web.Server, error) {
	eng := rules.NewEngine(rules.DirFor(r.Dir), cfg)
	eng.SetLogger(lg)
	st.Linter = eng
	au := auth.New(d)
	au.Secure, au.Logger = secure, lg
	hub := events.New()
	// after a push: drop the cached HEAD, then tell open pages
	invalidate := func(eng string) {
		st.Invalidate(eng)
		hub.Publish(events.Event{Eng: eng, Kind: events.Push})
	}
	tokens := auth.NewTokens(d)
	gs := gitServer(r, au, tokens, st, exe, invalidate)
	gs.Logger = lg
	if err := gs.Setup(); err != nil {
		return nil, fmt.Errorf("git setup: %w", err)
	}
	ix := index.New(st, r)
	mcpSrv := mcpServer(st, ix, eng, cfg, au.Users)
	mcpSrv.Logger = lg
	box, err := secret.Open(r.Dir)
	if err != nil {
		return nil, fmt.Errorf("secret key: %w", err)
	}
	return &web.Server{Store: st, Index: ix, Auth: au, Cfg: cfg, Rules: eng, Git: gs.Handler(), Export: exportRunner(r.Dir),
		MCP: mcpSrv.HTTPHandler(tokens), Events: hub, Tokens: tokens, Secret: box, HTTPS: secure, Version: buildVersion(), Source: source,
		MigrateStatus: func() []string { return legacyItems(r.Dir) }, SetupCode: setupCode, Logger: lg}, nil
}

// gitServer is the git endpoint of yars serve. The push hook it runs gets no
// AI key: AI rules do not run on a push (pushRunner). The lint endpoint runs
// in the server itself, with every rule (AI included), as Check does; for a
// token without the Run checks action, with the fast rules only.
func gitServer(r *gitrepo.Repo, au *auth.Auth, tokens *auth.Tokens, st *store.Store, exe string, invalidate func(string)) *gitserve.Server {
	return &gitserve.Server{Repo: r, Auth: au, HookCmd: hookCmd(exe, r.Dir), Sync: st.SyncPointers, Invalidate: invalidate,
		Receive: st.ReceivePush, Tokens: tokens, CanSee: st.CanSee, Lint: st.LintContent}
}

// serve runs the server until ctx is cancelled, then stops it: queued
// checks are dropped and none starts any more, new connections are refused,
// requests in flight get stopGrace to finish, the background workers stop,
// fixes with AI stop asking, running checks get stopGrace, the database
// closes.
// With hs.TLSConfig set it serves HTTPS with that configuration's
// certificate.
func serve(ctx context.Context, ln net.Listener, hs *http.Server, srv *web.Server, st *store.Store, d *db.DB) error {
	// Shutdown does not wait for open event streams: they end (and the pages
	// reconnect) when the stop begins, with the workers
	hs.RegisterOnShutdown(srv.Close)
	lg := logs.Or(srv.Logger)
	served := make(chan error, 1)
	go func() {
		if hs.TLSConfig != nil {
			served <- hs.ServeTLS(ln, "", "")
			return
		}
		served <- hs.Serve(ln)
	}()
	var err error
	select {
	case err = <-served: // could not serve at all
		st.StopChecks()
	case <-ctx.Done():
		lg.Info("yars stopping")
		// before the requests' grace: no queued check starts in it, and a
		// check asked for meanwhile fails at once
		st.StopChecks()
		sctx, cancel := context.WithTimeout(context.Background(), stopGrace)
		if serr := hs.Shutdown(sctx); serr != nil {
			lg.Warn("stop: requests still running after the grace", "grace", stopGrace.String(), "err", serr)
			hs.Close()
		}
		cancel()
		err = <-served
	}
	srv.Close()
	// a Fix with AI answers what it has left without the AI and starts no
	// check, so it ends well within the grace
	st.StopFixes()
	checks := make(chan struct{})
	go func() { st.WaitChecks(); close(checks) }()
	select {
	case <-checks:
	case <-time.After(stopGrace):
		lg.Warn("stop: checks still running after the grace", "grace", stopGrace.String())
	}
	d.Close()
	if errors.Is(err, http.ErrServerClosed) {
		lg.Info("yars stopped")
		return nil
	}
	return err
}
