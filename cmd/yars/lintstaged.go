package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// lintTimeout bounds the whole hook run: the server's AI rules can take as
// long as a Check does, but a commit never waits longer than this.
var lintTimeout = 120 * time.Second

// lintURL turns an origin URL (http[s]://host[:port]/git/e/<id>[.git]) into
// its lint endpoint (without the login a URL may carry); ok is false for any
// other URL.
func lintURL(origin string) (string, bool) {
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", false
	}
	id, ok := strings.CutPrefix(strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git"), "/git/e/")
	if !ok || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	out := url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/git/e/" + id + "/lint"}
	return out.String(), true
}

// errNoLogin: git has no saved login for the URL.
var errNoLogin = errors.New("no saved login")

// gitCmd is git in dir under ctx: killed when the run's time is up, and its
// pipes closed a second later even when a child it started (a credential
// helper) still holds them.
func gitCmd(ctx context.Context, dir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	cmd.WaitDelay = time.Second
	return cmd
}

// gitCredential asks git's credential helper for the login of url, never
// interactively (no prompt, no askpass, no helper dialog), within ctx; a URL
// that carries user:pass@ uses that.
func gitCredential(ctx context.Context, dir, rawURL string) (user, pass string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	if p, ok := u.User.Password(); ok && u.User.Username() != "" {
		return u.User.Username(), p, nil
	}
	cmd := gitCmd(ctx, dir, "-c", "credential.interactive=false", "credential", "fill")
	cmd.Stdin = strings.NewReader("url=" + rawURL + "\n\n")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=", "GCM_INTERACTIVE=never")
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "", "", ctx.Err()
	}
	if err != nil {
		return "", "", errNoLogin
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "username":
			user = v
		case "password":
			pass = v
		}
	}
	if user == "" || pass == "" {
		return "", "", errNoLogin
	}
	return user, pass, nil
}

// loginInURL reports whether rawURL carries a password (user:pass@).
func loginInURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return false
	}
	_, ok := u.User.Password()
	return ok
}

// rejectCredential tells git's credential helper that a login was refused,
// so it is not offered again (git credential reject, as git does after a
// 401), never interactively.
func rejectCredential(ctx context.Context, dir, rawURL, user, pass string) {
	cmd := gitCmd(ctx, dir, "-c", "credential.interactive=false", "credential", "reject")
	cmd.Stdin = strings.NewReader("url=" + rawURL + "\nusername=" + user + "\npassword=" + pass + "\n\n")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=", "GCM_INTERACTIVE=never")
	cmd.Run()
}

// stagedFindings lists the finding.md files staged in the clone at dir
// (added, copied or modified; a moved one counts as added: no rename
// detection, whatever diff.renames says).
func stagedFindings(ctx context.Context, dir string) ([]string, error) {
	out, err := gitCmd(ctx, dir, "diff", "--cached", "--no-renames", "--name-only", "--diff-filter=ACM", "-z").Output()
	if err != nil {
		return nil, fmt.Errorf("%s is not a git clone: %w", dir, err)
	}
	var paths []string
	for _, p := range strings.Split(string(out), "\x00") {
		seg := strings.Split(p, "/")
		if len(seg) == 3 && seg[0] == "findings" && seg[1] != "" && seg[2] == "finding.md" {
			paths = append(paths, p)
		}
	}
	return paths, nil
}

// lintAnswer is the server's answer for one finding.
type lintAnswer struct {
	Violations []struct {
		Rule, Level, Message, Target, Quote string
	} `json:"violations"`
	Error string `json:"error"`
}

// lintStaged sends the findings staged in the engagement clone at dir to its
// server and prints what the server found. It returns the number of errors
// and warnings; err is set only for a problem with the clone itself. When
// the server cannot be asked (down, slow, the login refused) it says so in
// one line and counts nothing: a commit is never held up by it. warnOnly
// adds "(commit not blocked)" to the last line.
func lintStaged(ctx context.Context, dir string, out io.Writer, warnOnly bool) (errs, warns int, err error) {
	paths, err := stagedFindings(ctx, dir)
	if err != nil || len(paths) == 0 {
		return 0, 0, err
	}
	originOut, _ := gitCmd(ctx, dir, "config", "--get", "remote.origin.url").Output()
	origin := strings.TrimSpace(string(originOut))
	endpoint, ok := lintURL(origin)
	if !ok {
		fmt.Fprintln(out, "yars: this clone's origin is not a YARS engagement (/git/e/<id>); nothing checked")
		return 0, 0, nil
	}
	host := strings.TrimPrefix(strings.TrimPrefix(endpoint, "http://"), "https://")
	host, _, _ = strings.Cut(host, "/")
	user, pass, err := gitCredential(ctx, dir, origin)
	if ctx.Err() != nil {
		fmt.Fprintf(out, "yars: could not ask %s: no answer within %s; nothing checked\n", host, lintTimeout)
		return 0, 0, nil
	}
	if err != nil {
		fmt.Fprintf(out, "yars: no saved login for %s; save one for git (a credential helper, then git fetch once; or a Git token in the clone URL) and commit again\n", host)
		return 0, 0, nil
	}
	client, err := gitHTTPClient(ctx, dir, origin)
	if err != nil {
		fmt.Fprintf(out, "yars: could not ask %s: %v; nothing checked\n", host, err)
		return 0, 0, nil
	}
	// read every staged finding, then ask about them, up to lintParallel at a
	// time (the server's AI rules are slow); only when every answer is in is
	// anything printed: a failure part way prints only itself
	raws := make([][]byte, len(paths))
	for i, p := range paths {
		raw, err := gitCmd(ctx, dir, "show", ":"+p).Output()
		if ctx.Err() != nil {
			fmt.Fprintf(out, "yars: could not ask %s: no answer within %s; nothing checked\n", host, lintTimeout)
			return 0, 0, nil
		}
		if err != nil {
			return 0, 0, fmt.Errorf("read %s from the index: %w", p, err)
		}
		raws[i] = raw
	}
	type result struct {
		path string
		a    lintAnswer
		code int
	}
	results := make([]result, len(paths))
	// the login first, with one cheap request: a refused one costs one
	// failed attempt (the lockout counts git and website logins alike), not
	// one per finding, and a login from git's helper is forgotten, as git
	// does after a 401; a good one is then cached by the server
	if code, reason := probeLogin(ctx, client, endpoint, user, pass); reason != "" {
		if code == http.StatusUnauthorized && !loginInURL(origin) {
			rejectCredential(ctx, dir, origin, user, pass)
		}
		fmt.Fprintf(out, "yars: could not ask %s: %s; nothing checked\n", host, reason)
		return 0, 0, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu     sync.Mutex
		failed string // the first failure's reason: it is the answer
		wg     sync.WaitGroup
	)
	sem := make(chan struct{}, lintParallel)
	for i, p := range paths {
		wg.Add(1)
		go func(i int, p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			a, code, reason := askLint(ctx, client, endpoint, user, pass, raws[i])
			mu.Lock()
			defer mu.Unlock()
			if reason != "" {
				if failed == "" {
					failed = reason
					cancel() // the others need not wait
				}
				return
			}
			results[i] = result{p, a, code}
		}(i, p)
	}
	wg.Wait()
	for _, r := range results {
		if r.path == "" && failed == "" { // not asked: the time ran out first
			failed = fmt.Sprintf("no answer within %s", lintTimeout)
		}
	}
	if failed != "" {
		fmt.Fprintf(out, "yars: could not ask %s: %s; nothing checked\n", host, failed)
		return 0, 0, nil
	}
	for _, r := range results {
		if r.code == http.StatusUnprocessableEntity {
			fmt.Fprintf(out, "%s error parse: %s\n", r.path, r.a.Error)
			errs++
			continue
		}
		for _, v := range r.a.Violations {
			level := v.Level
			cannot := v.Target == "rules" || v.Target == "ai" // a broken rule, no AI provider
			if cannot {
				level = "could not run" // as on push; it counts as neither
			}
			line := fmt.Sprintf("%s %s %s: %s", r.path, level, v.Rule, v.Message)
			if v.Quote != "" {
				line += fmt.Sprintf(" (%q)", v.Quote)
			}
			fmt.Fprintln(out, line+" ["+v.Target+"]")
			switch {
			case cannot:
			case v.Level == "error":
				errs++
			default:
				warns++
			}
		}
	}
	last := fmt.Sprintf("yars: %d errors, %d warnings in %d findings", errs, warns, len(results))
	if warnOnly {
		last += " (commit not blocked)"
	}
	fmt.Fprintln(out, last)
	return errs, warns, nil
}

// lintParallel is how many findings are asked about at a time.
const lintParallel = 4

// lintDialTimeout bounds connecting to the server.
const lintDialTimeout = 10 * time.Second

// gitHTTPClient is an HTTP client with git's own settings for the URL
// (http.sslCAInfo, http.sslVerify, http.proxy, and their GIT_SSL_*
// variables), so a clone that reaches its server through them needs
// nothing more.
func gitHTTPClient(ctx context.Context, dir, origin string) (*http.Client, error) {
	get := func(typ, key string) string {
		out, _ := gitCmd(ctx, dir, "config", "--type="+typ, "--get-urlmatch", key, origin).Output()
		return strings.TrimSpace(string(out))
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	// a network that drops packets (offline, VPN down) fails in seconds; the
	// answer itself may take as long as the run allows
	tr.DialContext = (&net.Dialer{Timeout: lintDialTimeout, KeepAlive: 30 * time.Second}).DialContext
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	ca := os.Getenv("GIT_SSL_CAINFO")
	if ca == "" {
		ca = get("path", "http.sslCAInfo")
	}
	if ca != "" {
		b, err := os.ReadFile(ca)
		if err != nil {
			return nil, fmt.Errorf("http.sslCAInfo: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("http.sslCAInfo %s: no certificate", ca)
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	if os.Getenv("GIT_SSL_NO_VERIFY") != "" || get("bool", "http.sslVerify") == "false" {
		tr.TLSClientConfig.InsecureSkipVerify = true // as git does with this setting
	}
	if p := get("string", "http.proxy"); p != "" {
		if !strings.Contains(p, "://") {
			p = "http://" + p // git's default scheme for a proxy
		}
		u, err := url.Parse(p)
		if err != nil {
			return nil, fmt.Errorf("http.proxy: %w", err)
		}
		tr.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Transport: tr}, nil
}

// probeLogin checks the login with a GET to the lint URL, which the server
// answers 405 only after the login, the team and the token's engagements
// passed (nothing runs). reason is set when the findings cannot be asked:
// a refused login (401), not on the team (403), no such endpoint or
// engagement (404), a server error.
func probeLogin(ctx context.Context, client *http.Client, endpoint, user, pass string) (code int, reason string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err.Error()
	}
	req.SetBasicAuth(user, pass)
	resp, err := client.Do(req)
	if err != nil {
		return 0, requestReason(ctx, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	switch c := resp.StatusCode; {
	case c == http.StatusUnauthorized:
		return c, "login refused"
	case c == http.StatusForbidden || c == http.StatusNotFound || c >= 500:
		return c, statusReason(resp.Status, body)
	}
	return resp.StatusCode, ""
}

// requestReason is the line's reason for a request that got no answer.
func requestReason(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return fmt.Sprintf("no answer within %s", lintTimeout)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return err.Error()
}

// statusReason is the line's reason for an answer that is not a result:
// its status and the first line of its body.
func statusReason(status string, body []byte) string {
	if first, _, _ := strings.Cut(strings.TrimSpace(string(body)), "\n"); first != "" && len(first) <= 200 {
		return status + ": " + first
	}
	return status
}

// askLint posts one finding; reason is set when the server could not be
// asked (it is the line's reason).
func askLint(ctx context.Context, client *http.Client, endpoint, user, pass string, raw []byte) (a lintAnswer, code int, reason string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return a, 0, err.Error()
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("Content-Type", "text/markdown; charset=utf-8")
	resp, err := client.Do(req)
	if err != nil {
		return a, 0, requestReason(ctx, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return a, 0, requestReason(ctx, err)
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusUnprocessableEntity:
		if err := json.Unmarshal(body, &a); err != nil {
			return a, 0, "an answer that is not a check result"
		}
		if resp.StatusCode == http.StatusUnprocessableEntity && a.Error == "" {
			a.Error = "the file does not parse"
		}
		return a, resp.StatusCode, ""
	case http.StatusUnauthorized:
		return a, resp.StatusCode, "login refused"
	}
	return a, 0, statusReason(resp.Status, body)
}
