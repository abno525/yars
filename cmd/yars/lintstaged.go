package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
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

// gitCredential asks git's credential helper for the login of url (never a
// prompt); a URL that carries user:pass@ uses that.
func gitCredential(dir, rawURL string) (user, pass string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	if p, ok := u.User.Password(); ok && u.User.Username() != "" {
		return u.User.Username(), p, nil
	}
	cmd := exec.Command("git", "-C", dir, "credential", "fill")
	cmd.Stdin = strings.NewReader("url=" + rawURL + "\n\n")
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=")
	out, err := cmd.Output()
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

// stagedFindings lists the finding.md files staged in the clone at dir
// (added, copied or modified).
func stagedFindings(dir string) ([]string, error) {
	out, err := exec.Command("git", "-C", dir, "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z").Output()
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
	paths, err := stagedFindings(dir)
	if err != nil || len(paths) == 0 {
		return 0, 0, err
	}
	originOut, _ := exec.Command("git", "-C", dir, "config", "--get", "remote.origin.url").Output()
	origin := strings.TrimSpace(string(originOut))
	endpoint, ok := lintURL(origin)
	if !ok {
		fmt.Fprintln(out, "yars: this clone's origin is not a YARS engagement (/git/e/<id>); nothing checked")
		return 0, 0, nil
	}
	host := strings.TrimPrefix(strings.TrimPrefix(endpoint, "http://"), "https://")
	host, _, _ = strings.Cut(host, "/")
	user, pass, err := gitCredential(dir, origin)
	if err != nil {
		fmt.Fprintf(out, "yars: no saved login for %s; run git fetch once, then commit again\n", host)
		return 0, 0, nil
	}
	// ask about every finding first: a failure part way prints only itself
	type result struct {
		path string
		a    lintAnswer
		code int
	}
	var results []result
	for _, p := range paths {
		raw, err := exec.Command("git", "-C", dir, "show", ":"+p).Output()
		if err != nil {
			return 0, 0, fmt.Errorf("read %s from the index: %w", p, err)
		}
		a, code, reason := askLint(ctx, endpoint, user, pass, raw)
		if reason != "" {
			fmt.Fprintf(out, "yars: could not ask %s: %s; nothing checked\n", host, reason)
			return 0, 0, nil
		}
		results = append(results, result{p, a, code})
	}
	for _, r := range results {
		if r.code == http.StatusUnprocessableEntity {
			fmt.Fprintf(out, "%s error parse: %s\n", r.path, r.a.Error)
			errs++
			continue
		}
		for _, v := range r.a.Violations {
			line := fmt.Sprintf("%s %s %s: %s", r.path, v.Level, v.Rule, v.Message)
			if v.Quote != "" {
				line += fmt.Sprintf(" (%q)", v.Quote)
			}
			fmt.Fprintln(out, line+" ["+v.Target+"]")
			if v.Level == "error" {
				errs++
			} else {
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

// askLint posts one finding; reason is set when the server could not be
// asked (it is the line's reason).
func askLint(ctx context.Context, endpoint, user, pass string, raw []byte) (a lintAnswer, code int, reason string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return a, 0, err.Error()
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("Content-Type", "text/markdown; charset=utf-8")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return a, 0, fmt.Sprintf("no answer within %s", lintTimeout)
		}
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return a, 0, err.Error()
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		if ctx.Err() != nil {
			return a, 0, fmt.Sprintf("no answer within %s", lintTimeout)
		}
		return a, 0, err.Error()
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
		return a, 0, "login refused"
	}
	msg := resp.Status
	if first, _, _ := strings.Cut(strings.TrimSpace(string(body)), "\n"); first != "" && len(first) <= 200 {
		msg += ": " + first
	}
	return a, 0, msg
}
