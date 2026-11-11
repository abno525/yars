package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/events"
	"yars/internal/gitserve"
	"yars/internal/index"
	"yars/internal/mcp"
	"yars/internal/rules"
	"yars/internal/secret"
	"yars/internal/store"
	"yars/internal/web"
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

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	data := dataFlag(fs)
	addr := fs.String("addr", ":8080", "listen address")
	cert := fs.String("tls-cert", "", "serve HTTPS with this certificate file (needs --tls-key)")
	key := fs.String("tls-key", "", "the certificate's private key file (needs --tls-cert)")
	https := fs.Bool("https", false, "a proxy in front serves HTTPS: Secure cookies and HSTS")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if (*cert == "") != (*key == "") {
		return fmt.Errorf("--tls-cert and --tls-key go together")
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
	r, err := openData(fs, *data)
	if err != nil {
		return err
	}
	// a push cut off mid-way must not leave its tree (or config) behind
	if err := gitserve.RestoreTrees(r); err != nil {
		return fmt.Errorf("restore work trees: %w", err)
	}
	cfg, err := config.Load(r.Dir)
	if err != nil {
		return err
	}
	if items := legacyItems(r.Dir); len(items) > 0 {
		return fmt.Errorf("this data directory still keeps accounts, workflow state or chat in files (%s); run: yars migrate --data %s", strings.Join(items, ", "), r.Dir)
	}
	d, err := dataDB(r.Dir)
	if err != nil {
		return err
	}
	if users, _ := d.Users(); len(users) == 0 {
		log.Println("no accounts yet: open the web page to set up the first admin (/setup), or run: yars useradd --data", r.Dir, "--role director --admin <name>")
	}
	st := store.New(r, cfg, d)
	if err := backfillTeams(st, d); err != nil {
		return fmt.Errorf("team backfill: %w", err)
	}
	// before any request: a Make finding claim now is one a stop cut off
	if err := d.ResetBoardClaims(); err != nil {
		return fmt.Errorf("team board: %w", err)
	}
	eng := rules.NewEngine(rules.DirFor(r.Dir), cfg)
	st.Linter = eng
	au := auth.New(d)
	au.Secure = secure
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := ensureIgnored(r); err != nil {
		return fmt.Errorf("ignore server files: %w", err)
	}
	if err := st.SyncPointers(); err != nil {
		return fmt.Errorf("update engagement pointers: %w", err)
	}
	hub := events.New()
	// after a push: drop the cached HEAD, then tell open pages
	invalidate := func(eng string) {
		st.Invalidate(eng)
		hub.Publish(events.Event{Eng: eng, Kind: events.Push})
	}
	tokens := auth.NewTokens(d)
	gs := &gitserve.Server{Repo: r, Auth: au, HookCmd: hookCmd(exe, r.Dir), Sync: st.SyncPointers, Invalidate: invalidate,
		Receive: st.ReceivePush, Tokens: tokens, CanSee: st.CanSee}
	if cfg.AI.APIKeyEnv != "" {
		gs.InheritEnv = []string{cfg.AI.APIKeyEnv} // AI rules run on pushes too
	}
	if err := gs.Setup(); err != nil {
		return fmt.Errorf("git setup: %w", err)
	}
	ix := index.New(st, r)
	mcpSrv := &mcp.Server{Store: st, Index: ix, Rules: eng, Cfg: cfg, Users: au.Users}
	box, err := secret.Open(r.Dir)
	if err != nil {
		return fmt.Errorf("secret key: %w", err)
	}
	srv := &web.Server{Store: st, Index: ix, Auth: au, Cfg: cfg, Rules: eng, Git: gs.Handler(), Export: exportRunner(r.Dir),
		MCP: mcpSrv.HTTPHandler(tokens), Events: hub, Tokens: tokens, Secret: box, HTTPS: secure,
		MigrateStatus: func() []string { return legacyItems(r.Dir) }}
	hs := srv.HTTPServer(*addr)
	hs.TLSConfig = tlsCfg
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("yars serving %s on %s", r.Dir, *addr)
	return serve(ctx, ln, hs, srv, st, d)
}

// serve runs the server until ctx is cancelled, then stops it: new
// connections are refused, requests in flight get stopGrace to finish, the
// background workers stop, running checks get stopGrace, the database closes.
// With hs.TLSConfig set it serves HTTPS with that configuration's
// certificate.
func serve(ctx context.Context, ln net.Listener, hs *http.Server, srv *web.Server, st *store.Store, d *db.DB) error {
	// Shutdown does not wait for open event streams: they end (and the pages
	// reconnect) when the stop begins, with the workers
	hs.RegisterOnShutdown(srv.Close)
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
	case <-ctx.Done():
		log.Println("yars stopping")
		sctx, cancel := context.WithTimeout(context.Background(), stopGrace)
		if serr := hs.Shutdown(sctx); serr != nil {
			log.Printf("stop: requests still running after %s: %v", stopGrace, serr)
			hs.Close()
		}
		cancel()
		err = <-served
	}
	srv.Close()
	checks := make(chan struct{})
	go func() { st.WaitChecks(); close(checks) }()
	select {
	case <-checks:
	case <-time.After(stopGrace):
		log.Printf("stop: checks still running after %s", stopGrace)
	}
	d.Close()
	if errors.Is(err, http.ErrServerClosed) {
		log.Println("yars stopped")
		return nil
	}
	return err
}
