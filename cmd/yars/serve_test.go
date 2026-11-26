package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/finding"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/index"
	"github.com/abno525/yars/internal/logs"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/store"
	"github.com/abno525/yars/internal/web"
)

// startData readies a data folder as a start of yars serve does, without a
// log: startConfig, then prepareData.
func startData(r *gitrepo.Repo) (config.Config, *db.DB, *store.Store, error) {
	cfg, err := startConfig(r)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	d, st, err := prepareData(r, cfg, nil)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	return cfg, d, st, nil
}

// A certificate needs its key and the key its certificate.
func TestServeTLSFlagsNeedBoth(t *testing.T) {
	data := t.TempDir() // never the real default folder, even if the check broke
	for _, args := range [][]string{{"--tls-cert", "x"}, {"--tls-key", "y"}} {
		err := cmdServe(append([]string{"--data", data}, args...))
		if err == nil || err.Error() != "--tls-cert and --tls-key go together" {
			t.Fatalf("%v: err %v", args, err)
		}
	}
	if err := cmdServe([]string{"--data", data, "--https", "--tls-cert", "x"}); err == nil || !strings.Contains(err.Error(), "go together") {
		t.Fatalf("--https with only a certificate: %v", err)
	}
	// a certificate that does not load stops before the data folder is read
	err := cmdServe([]string{"--data", data, "--tls-cert", "missing.pem", "--tls-key", "missing.key"})
	if err == nil || !strings.HasPrefix(err.Error(), "--tls-cert, --tls-key:") {
		t.Fatalf("missing certificate: %v", err)
	}
}

// A start without accounts makes a setup code and logs it, with the way to
// make the first admin from the shell (which needs no code); a start with an
// account makes none and logs nothing, so /setup stays closed.
func TestServeSetupCode(t *testing.T) {
	dir := t.TempDir()
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	d := openDB(t, dir)
	lg, out := logs.NewRecorder()
	code := firstRunCode(d, config.Default(), dir, lg)
	recs := out.Records()
	if len(code) != 14 || len(recs) != 1 || recs[0].Str("setup_code") != code {
		t.Fatalf("code %q, log:\n%s", code, out.Text())
	}
	if !strings.Contains(recs[0].Msg, "/setup") || recs[0].Str("command") != "yars useradd --data "+dir+" --role director --admin <name>" {
		t.Fatalf("log:\n%s", out.Text())
	}
	if again := firstRunCode(d, config.Default(), dir, lg); again == code {
		t.Fatal("two starts made the same code")
	}
	// the simple workflow has no roles
	out.Reset()
	simple := config.Default()
	simple.Workflow = config.WorkflowSimple
	if firstRunCode(d, simple, dir, lg); strings.Contains(out.Text(), "--role") || !strings.Contains(out.Text(), "--admin <name>") {
		t.Fatalf("simple log:\n%s", out.Text())
	}
	// the code is written whatever log.level says: /setup needs it
	var stderr bytes.Buffer
	cfg := config.Default()
	cfg.Log.Level = "error"
	quiet, _ := serverLog(&stderr, cfg, "")
	quiet.Warn("hidden at error")
	code = firstRunCode(d, cfg, dir, quiet)
	if got := stderr.String(); strings.Contains(got, "hidden") || !strings.Contains(got, "setup_code="+code) || strings.Count(got, "\n") != 1 {
		t.Fatalf("log.level error: code %q, log:\n%s", code, got)
	}
	// the first admin made from the shell, as the README has it: no code
	pw, err := auth.HashPassword("long enough pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.AddUser(config.User{Username: "ann", Role: "director", IsAdmin: true, PasswordHash: pw}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := firstRunCode(d, config.Default(), dir, lg); code != "" || len(out.Records()) != 0 {
		t.Fatalf("with an account: code %q, log:\n%s", code, out.Text())
	}
}

// A start without base_url says so once, naming the key; with it, nothing.
func TestServeWarnsWithoutBaseURL(t *testing.T) {
	lg, out := logs.NewRecorder()
	cfg := config.Default()
	warnNoBaseURL(cfg, lg)
	if recs := out.Records(); len(recs) != 1 || recs[0].Level != slog.LevelWarn || !strings.Contains(recs[0].Msg, "base_url is not set in .yars/config.yaml") {
		t.Fatalf("log:\n%s", out.Text())
	}
	out.Reset()
	cfg.BaseURL = "https://yars.example.com"
	if warnNoBaseURL(cfg, lg); len(out.Records()) != 0 {
		t.Fatalf("with base_url:\n%s", out.Text())
	}
}

// log.level and log.format of config.yaml shape the service log; --log-level
// goes over the file's level. A word that is no level stops the start with
// the key (or the flag) in the message, before the database is opened.
func TestServeLogLevelAndFormat(t *testing.T) {
	line := func(cfg config.Config, flag string) string {
		var buf bytes.Buffer
		lg, _ := serverLog(&buf, cfg, flag)
		lg.Debug("d")
		lg.Info("i")
		lg.Warn("w")
		return buf.String()
	}
	cfg := config.Default()
	if got := line(cfg, ""); strings.Contains(got, "msg=d") || !strings.Contains(got, "level=INFO msg=i") {
		t.Errorf("default: %q", got)
	}
	cfg.Log.Level = "warn"
	if got := line(cfg, ""); strings.Contains(got, "msg=i") || !strings.Contains(got, "level=WARN msg=w") {
		t.Errorf("log.level warn: %q", got)
	}
	if got := line(cfg, "debug"); !strings.Contains(got, "msg=d") {
		t.Errorf("--log-level debug over log.level warn: %q", got)
	}
	cfg.Log.Format = "json"
	if got := line(cfg, ""); !strings.HasPrefix(got, "{") || !strings.Contains(got, `"msg":"w"`) {
		t.Errorf("log.format json: %q", got)
	}

	// a bad flag: before the data folder is read
	err := cmdServe([]string{"--data", t.TempDir(), "--log-level", "loud"})
	if err == nil || err.Error() != `--log-level "loud" must be debug, info, warn or error` {
		t.Fatalf("--log-level loud: %v", err)
	}
	// a bad key in config.yaml: the start stops and names it
	dir := t.TempDir()
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for body, want := range map[string]string{
		"log:\n  level: loud\n":  `config: log.level "loud" must be debug, info, warn or error`,
		"log:\n  format: xml\n":  `config: log.format "xml" must be text or json`,
		"log:\n  level: DEBUG\n": `config: log.level "DEBUG" must be debug, info, warn or error`,
	} {
		if err := os.WriteFile(config.ConfigPath(dir), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := r.Commit([]string{".yars/config.yaml"}, "config", system); err != nil {
			t.Fatal(err)
		}
		err := cmdServe([]string{"--data", dir, "--addr", "127.0.0.1:0"})
		if err == nil || err.Error() != want {
			t.Fatalf("%q: %v", body, err)
		}
	}
}

// What net/http itself logs goes to the server's logger, never to the
// process-wide standard one.
func TestServeHTTPErrorLog(t *testing.T) {
	lg, out := logs.NewRecorder()
	hs := (&web.Server{Auth: auth.New(nil), Logger: lg}).HTTPServer("127.0.0.1:0")
	if hs.ErrorLog == nil {
		t.Fatal("the http.Server has no ErrorLog")
	}
	hs.ErrorLog.Print("http: TLS handshake error from 192.0.2.1:1: EOF\n")
	recs := out.With("http server")
	if len(recs) != 1 || recs[0].Level != slog.LevelWarn || recs[0].Str("err") != "http: TLS handshake error from 192.0.2.1:1: EOF" {
		t.Fatalf("log:\n%s", out.Text())
	}
}

// A config.yaml that names a variable without the YARS_ prefix stops the
// start, before the database is opened, with the key and the fix; the fix
// committed in the data folder (as the message says) starts.
func TestServeRefusesOtherEnvNames(t *testing.T) {
	dir := t.TempDir()
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	commit := func(name string) {
		t.Helper()
		if err := os.WriteFile(config.ConfigPath(dir), []byte("ai:\n  provider: openai\n  base_url: https://llm.example/v1\n  api_key_env: "+name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := r.Commit([]string{".yars/config.yaml"}, "config", system); err != nil {
			t.Fatal(err)
		}
	}
	commit("OPENAI_API_KEY")
	err = cmdServe([]string{"--data", dir, "--addr", "127.0.0.1:0"})
	if err == nil {
		t.Fatal("served")
	}
	for _, want := range []string{"ai.api_key_env", `"OPENAI_API_KEY"`, "YARS_OPENAI_API_KEY", "commit"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("%q lacks %q", err, want)
		}
	}
	commit("YARS_OPENAI_API_KEY")
	cfg, err := startConfig(r)
	if err != nil {
		t.Fatalf("after the fix: %v", err)
	}
	d, _, err := prepareData(r, cfg, nil)
	if err != nil {
		t.Fatalf("after the fix: %v", err)
	}
	d.Close()
	if cfg.AI.APIKeyEnv != "YARS_OPENAI_API_KEY" {
		t.Fatalf("config %+v", cfg.AI)
	}
}

// The push hook gets no AI key: AI rules do not run on a push.
func TestHookEnvHasNoAIKey(t *testing.T) {
	dir := t.TempDir()
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d := openDB(t, dir)
	cfg := config.Default()
	cfg.AI.APIKeyEnv = "YARS_AI_KEY"
	t.Setenv("YARS_AI_KEY", "sk-secret")
	st := store.New(r, cfg, d)
	au := auth.New(d)
	gs := gitServer(r, au, auth.NewTokens(d), st, "yars", func(string) {})
	if len(gs.InheritEnv) != 0 {
		t.Fatalf("the hook inherits %v", gs.InheritEnv)
	}
	// M30: the lint endpoint is on; it runs in the server, with every rule
	if gs.Lint == nil {
		t.Fatal("the git server has no lint endpoint")
	}
	if _, err := gs.Lint(context.Background(), "nope", []byte("---\nid: F-001\ntitle: x\n---\n"), rules.All); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("lint of an unknown engagement: %v", err)
	}
}

// Told to stop, the server finishes the request in flight, ends open event
// streams, refuses new connections and closes the database.
func TestServeStopsCleanly(t *testing.T) {
	dir := t.TempDir()
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(r.Dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := dataDB(r.Dir)
	if err != nil {
		t.Fatal(err)
	}
	pw, err := auth.HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.AddUser(config.User{Username: "ann", Role: "director", PasswordHash: pw}); err != nil {
		t.Fatal(err)
	}
	st := store.New(r, cfg, d)
	au := auth.New(d)
	tok, ok := au.Login("ann", "pw")
	if !ok {
		t.Fatal("login failed")
	}
	srv := &web.Server{Store: st, Index: index.New(st, r), Auth: au, Cfg: cfg}
	hs := srv.HTTPServer("127.0.0.1:0")
	inner := hs.Handler
	started := make(chan struct{})
	var once sync.Once
	hs.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/slow" {
			once.Do(func() { close(started) })
			time.Sleep(200 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			return
		}
		inner.ServeHTTP(w, req)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, hs, srv, st, d) }()

	// an open page's event stream
	req, _ := http.NewRequest("GET", "http://"+addr+"/events", nil)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: tok})
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	if stream.StatusCode != http.StatusOK {
		t.Fatalf("events %d", stream.StatusCode)
	}
	if _, err := bufio.NewReader(stream.Body).ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	got := make(chan int, 1)
	go func() {
		resp, err := http.Get("http://" + addr + "/slow")
		if err != nil {
			got <- -1
			return
		}
		resp.Body.Close()
		got <- resp.StatusCode
	}()
	<-started // the request is in flight
	cancel()
	if code := <-got; code != http.StatusOK {
		t.Fatalf("the request in flight got %d", code)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return within 5 s")
	}
	if c, err := net.Dial("tcp", addr); err == nil {
		c.Close()
		t.Fatal("the server still accepts connections")
	}
	if err := d.Ping(); err == nil {
		t.Fatal("the database is still open")
	}
}

// holdLinter holds each check run until a token comes on release.
type holdLinter struct {
	release chan struct{}
	began   atomic.Int32
}

func (l *holdLinter) Lint(_ context.Context, _ *finding.Finding, k rules.Kind) []rules.Violation {
	if k == rules.All {
		l.began.Add(1)
		<-l.release
	}
	return nil
}

// Q3: told to stop, the server drops the queued checks (failed as
// interrupted) at once, before the requests in flight end, so none starts
// in their grace; it waits only for the run under way.
func TestServeDropsQueuedChecks(t *testing.T) {
	dir := t.TempDir()
	if err := initData(dir); err != nil {
		t.Fatal(err)
	}
	r, err := gitrepo.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := dataDB(r.Dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Checks.MaxRunning = 1
	st := store.New(r, cfg, d)
	l := &holdLinter{release: make(chan struct{})}
	st.Linter = l
	a := gitrepo.Author{Name: "ann", Email: "ann@yars.local"}
	if err := st.CreateEngagement(store.Engagement{ID: "acme", Name: "ACME"}, a); err != nil {
		t.Fatal(err)
	}
	u := config.User{Username: "ann", Role: "director"}
	var runs []db.CheckRun
	for _, title := range []string{"One", "Two"} {
		f, err := st.CreateFinding("acme", title, a)
		if err != nil {
			t.Fatal(err)
		}
		run, err := st.StartCheck("acme", f.Dir, u)
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, run)
	}
	if runs[1].State != store.RunQueued {
		t.Fatalf("second run %+v", runs[1])
	}
	srv := &web.Server{Store: st, Index: index.New(st, r), Auth: auth.New(d), Cfg: cfg}
	hs := srv.HTTPServer("127.0.0.1:0")
	inner := hs.Handler
	held, hold := make(chan struct{}), make(chan struct{})
	var once sync.Once
	hs.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/slow" {
			once.Do(func() { close(held) })
			<-hold
			return
		}
		inner.ServeHTTP(w, req)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, ln, hs, srv, st, d) }()
	go func() {
		if resp, err := http.Get("http://" + ln.Addr().String() + "/slow"); err == nil {
			resp.Body.Close()
		}
	}()
	<-held // a request in flight
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if run, err := d.Run(runs[1].ID); err == nil && run.State == db.RunFailed && run.Error == "interrupted" {
			break
		}
		if time.Now().After(deadline) {
			close(hold)
			close(l.release)
			t.Fatal("the queued run was not dropped while a request was in flight")
		}
		time.Sleep(10 * time.Millisecond)
	}
	l.release <- struct{}{} // the run under way ends within the request's grace
	close(hold)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		close(l.release)
		t.Fatal("serve waits for the queued run")
	}
	if n := l.began.Load(); n != 1 {
		t.Fatalf("%d runs began", n)
	}
}
