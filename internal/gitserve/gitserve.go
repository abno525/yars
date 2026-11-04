// Package gitserve exposes the data repo over git smart HTTP (git
// http-backend) behind YARS accounts, and installs the pre-receive hook that
// enforces workflow and style rules on pushes.
package gitserve

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/gitrepo"
)

// RepoName is the fixed name in the clone URL: http(s)://host/git/yars.
const RepoName = "yars"

type Server struct {
	Repo *gitrepo.Repo
	Auth *auth.Auth
	// HookCmd is the command line the pre-receive hook execs (empty = no hook).
	HookCmd string
	// InheritEnv names extra environment variables passed to git and the
	// hook (e.g. the AI key variable, so AI rules also run on pushes).
	InheritEnv []string

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	user config.User
	exp  time.Time
}

// Setup configures the repo for pushes and (re)writes the pre-receive hook.
func (s *Server) Setup() error {
	gd, err := s.Repo.GitDir()
	if err != nil {
		return err
	}
	hooks := filepath.Join(gd, "hooks")
	for k, v := range map[string]string{
		"http.receivepack":            "true",
		"receive.denyCurrentBranch":   "updateInstead",
		"receive.denyNonFastForwards": "true",
		"receive.denyDeletes":         "true",
		"receive.fsckObjects":         "true",
		// a global/system core.hooksPath would silently skip our hook
		"core.hooksPath": hooks,
	} {
		if err := s.Repo.SetConfig(k, v); err != nil {
			return err
		}
	}
	hook := filepath.Join(hooks, "pre-receive")
	if s.HookCmd == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		return err
	}
	return os.WriteFile(hook, []byte("#!/bin/sh\nexec "+s.HookCmd+"\n"), 0o755)
}

// check verifies Basic credentials, caching successes for 10 minutes so git's
// several requests per operation don't each pay for bcrypt. A cached login
// still needs the account to exist with the same password hash, and uses the
// account's current role.
func (s *Server) check(user, pw string) (config.User, bool) {
	h := sha256.Sum256([]byte(user + ":" + pw))
	key := hex.EncodeToString(h[:])
	s.mu.Lock()
	if s.cache == nil {
		s.cache = map[string]cached{}
	}
	c, ok := s.cache[key]
	s.mu.Unlock()
	if ok && time.Now().Before(c.exp) {
		if cur, found := s.Auth.Lookup(user); found && cur.PasswordHash == c.user.PasswordHash {
			return cur, true
		}
		s.mu.Lock()
		delete(s.cache, key)
		s.mu.Unlock()
	}
	u, ok := s.Auth.Check(user, pw)
	if ok {
		s.mu.Lock()
		s.cache[key] = cached{u, time.Now().Add(10 * time.Minute)}
		s.mu.Unlock()
	}
	return u, ok
}

// Handler serves /git/yars/... via git http-backend.
func (s *Server) Handler() http.Handler {
	gitPath, gitErr := exec.LookPath("git")
	root := "/git/" + RepoName
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, root)
		if !ok || (rest != "" && rest[0] != '/') {
			http.NotFound(w, r)
			return
		}
		name, pw, ok := r.BasicAuth()
		var u config.User
		valid := false
		if ok { // no bcrypt for requests without credentials
			u, valid = s.check(name, pw)
		}
		if !valid {
			w.Header().Set("WWW-Authenticate", `Basic realm="yars", charset="UTF-8"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if gitErr != nil {
			http.Error(w, "git not available", http.StatusInternalServerError)
			return
		}
		h := &cgi.Handler{
			Path: gitPath,
			Root: root,
			Args: []string{"http-backend"},
			Dir:  s.Repo.Dir,
			Env: []string{
				"GIT_PROJECT_ROOT=" + s.Repo.Dir,
				"GIT_HTTP_EXPORT_ALL=1",
				"REMOTE_USER=" + u.Username,
				fmt.Sprintf("GIT_COMMITTER_NAME=%s", u.Username),
				"GIT_COMMITTER_EMAIL=" + u.GitAuthor().Email,
			},
			InheritEnv: s.inherit(),
		}
		// the identity travels as REMOTE_USER; don't leak the password into
		// the environment of git and the hook (HTTP_AUTHORIZATION)
		r2 := r.Clone(r.Context())
		r2.Header.Del("Authorization")
		h.ServeHTTP(w, r2)
	})
}

func (s *Server) inherit() []string {
	env := []string{"PATH", "HOME", "TMPDIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy"}
	return append(env, s.InheritEnv...)
}
