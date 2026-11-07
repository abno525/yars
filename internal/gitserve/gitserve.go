// Package gitserve exposes the data repos over git smart HTTP (git
// http-backend) behind YARS accounts, and installs the pre-receive hook that
// enforces the push rules: the main repo at /git/yars (settings plus every
// engagement as a submodule) and each engagement's own repo at /git/e/<id>.
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
	"regexp"
	"strings"
	"sync"
	"time"

	"yars/internal/auth"
	"yars/internal/config"
	"yars/internal/db"
	"yars/internal/gitrepo"
	"yars/internal/policy"
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
	// Sync, when set, brings the main repo's engagement pointers up to date;
	// it runs before the main repo is fetched.
	Sync func() error
	// Invalidate, when set, is told after every push which repo it went to
	// (an engagement id, "" for the main repo), so cached HEADs are dropped.
	Invalidate func(eng string)
	// Receive, when set, wraps each push (eng "" = the main repo): it must
	// call serve (git receiving the push as u) once, and can hold off
	// other writes meanwhile and tell what the push changed.
	Receive func(eng string, u config.User, serve func())
	// Tokens, when set, accepts git tokens (kind git) in place of the
	// password: a read-only token can fetch but not push, and a token
	// limited to engagements reaches only those (not the main repo).
	Tokens *auth.Tokens
	// CanSee, when set, decides who may reach an engagement's repo (its
	// team, directors, admins); others get 403.
	CanSee func(u config.User, eng string) bool

	mu    sync.Mutex
	cache map[string]cached
	ready map[string]bool // repos already configured for pushes
}

type cached struct {
	user config.User
	exp  time.Time
}

// Setup configures the main repo and every engagement repo for pushes and
// (re)writes their pre-receive hooks. Engagement repos created later are
// set up on their first request.
func (s *Server) Setup() error {
	if err := s.setupRepo(s.Repo); err != nil {
		return err
	}
	ents, _ := os.ReadDir(filepath.Join(s.Repo.Dir, "engagements"))
	for _, e := range ents {
		if r, ok := s.engRepo(e.Name()); ok {
			if err := s.setupRepo(r); err != nil {
				return err
			}
		}
	}
	return nil
}

// RestoreTrees puts the main repo's and every engagement repo's work tree
// back to HEAD. A push interrupted between git checking its tree out and
// moving the branch leaves a tree that is not HEAD; YARS commits everything
// it writes, so nothing else can be lost. Run it on start, before the config
// is loaded or anything is committed.
func RestoreTrees(main *gitrepo.Repo) error {
	if _, err := main.RestoreHead(); err != nil {
		return err
	}
	ents, _ := os.ReadDir(filepath.Join(main.Dir, "engagements"))
	for _, e := range ents {
		if !engIDRe.MatchString(e.Name()) || strings.Contains(e.Name(), "..") {
			continue
		}
		r, err := gitrepo.Open(filepath.Join(main.Dir, "engagements", e.Name()))
		if err != nil {
			continue // not a repository of its own
		}
		if _, err := r.RestoreHead(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) setupRepo(r *gitrepo.Repo) error {
	gd, err := r.GitDir()
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
		if err := r.SetConfig(k, v); err != nil {
			return err
		}
	}
	if s.HookCmd != "" {
		cmd := s.HookCmd
		// an engagement repo's hook names its engagement (ids are [A-Za-z0-9._-])
		if filepath.Dir(r.Dir) == filepath.Join(s.Repo.Dir, "engagements") && engIDRe.MatchString(filepath.Base(r.Dir)) {
			cmd += " --eng " + filepath.Base(r.Dir)
		}
		hook := filepath.Join(hooks, "pre-receive")
		if err := os.MkdirAll(hooks, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(hook, []byte("#!/bin/sh\nexec "+cmd+"\n"), 0o755); err != nil {
			return err
		}
	}
	s.mu.Lock()
	if s.ready == nil {
		s.ready = map[string]bool{}
	}
	s.ready[r.Dir] = true
	s.mu.Unlock()
	return nil
}

var engIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// engRepo opens engagements/<id> when it is a repository of its own.
func (s *Server) engRepo(id string) (*gitrepo.Repo, bool) {
	if !engIDRe.MatchString(id) || strings.Contains(id, "..") {
		return nil, false
	}
	r, err := gitrepo.Open(filepath.Join(s.Repo.Dir, "engagements", id))
	return r, err == nil
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

// mainServicePath accepts only git's own request paths under the main
// repo's URL, so nested repositories (engagements/<id>) can't be reached
// through it.
func mainServicePath(rest string) bool {
	switch rest {
	case "", "/info/refs", "/git-upload-pack", "/git-receive-pack", "/HEAD":
		return true
	}
	return strings.HasPrefix(rest, "/objects/") && !strings.Contains(rest, "..")
}

// route maps a request path to its repository, URL root and engagement id
// ("" for the main repo): /git/yars is the main repo, /git/e/<id> an
// engagement repo.
func (s *Server) route(p string) (*gitrepo.Repo, string, string, bool) {
	root := "/git/" + RepoName
	if rest, ok := strings.CutPrefix(p, root); ok && mainServicePath(rest) {
		return s.Repo, root, "", true
	}
	rest, ok := strings.CutPrefix(p, "/git/e/")
	if !ok {
		return nil, "", "", false
	}
	id, _, _ := strings.Cut(rest, "/")
	r, ok := s.engRepo(id)
	if !ok {
		return nil, "", "", false
	}
	return r, "/git/e/" + id, id, true
}

// Handler serves /git/yars/... and /git/e/<id>/... via git http-backend.
func (s *Server) Handler() http.Handler {
	gitPath, gitErr := exec.LookPath("git")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// authenticate first: without a login nothing reveals which
		// engagements exist
		name, pw, ok := r.BasicAuth()
		var u config.User
		var tok *db.TokenInfo
		valid := false
		switch {
		case !ok: // no bcrypt for requests without credentials
		case s.Tokens != nil && strings.HasPrefix(pw, "yars_"):
			var info db.TokenInfo
			u, info, valid = s.Tokens.Verify(pw, db.TokenGit)
			valid = valid && u.Username == name // the token's own account only
			tok = &info
		default:
			u, valid = s.check(name, pw)
		}
		if !valid {
			w.Header().Set("WWW-Authenticate", `Basic realm="yars", charset="UTF-8"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		repo, root, eng, ok := s.route(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		if eng != "" && s.CanSee != nil && !s.CanSee(u, eng) {
			http.Error(w, "not a member of this engagement", http.StatusForbidden)
			return
		}
		if tok != nil {
			if tok.Restricted() && (eng == "" || !tok.AllowsEng(eng)) {
				http.Error(w, "this token is not valid for this repository", http.StatusForbidden)
				return
			}
			if isPush(r) && !tok.Allows("create") && !tok.Allows("edit") {
				http.Error(w, "this token can fetch but not push", http.StatusForbidden)
				return
			}
		}
		if gitErr != nil {
			http.Error(w, "git not available", http.StatusInternalServerError)
			return
		}
		s.mu.Lock()
		ready := s.ready[repo.Dir]
		s.mu.Unlock()
		if !ready {
			if err := s.setupRepo(repo); err != nil {
				http.Error(w, "repository setup failed", http.StatusInternalServerError)
				return
			}
		}
		if repo == s.Repo && s.Sync != nil && strings.HasSuffix(r.URL.Path, "/info/refs") {
			// clones and fetches of the main repo see current engagement pointers
			if err := s.Sync(); err != nil {
				http.Error(w, "could not update engagement pointers", http.StatusInternalServerError)
				return
			}
		}
		env := []string{
			"GIT_PROJECT_ROOT=" + repo.Dir,
			"GIT_HTTP_EXPORT_ALL=1",
			"REMOTE_USER=" + u.Username,
			fmt.Sprintf("GIT_COMMITTER_NAME=%s", u.Username),
			"GIT_COMMITTER_EMAIL=" + u.GitAuthor().Email,
		}
		if tok != nil {
			// the hook checks each change against the token's scopes
			env = append(env, policy.TokenScopesEnv+"="+strings.Join(tok.Scopes, ","))
		}
		h := &cgi.Handler{
			Path:       gitPath,
			Root:       root,
			Args:       []string{"http-backend"},
			Dir:        repo.Dir,
			Env:        env,
			InheritEnv: s.inherit(),
		}
		// the identity travels as REMOTE_USER; don't leak the password into
		// the environment of git and the hook (HTTP_AUTHORIZATION)
		r2 := r.Clone(r.Context())
		r2.Header.Del("Authorization")
		receive := r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git-receive-pack")
		if receive && s.Receive != nil {
			s.Receive(eng, u, func() { h.ServeHTTP(w, r2) })
		} else {
			h.ServeHTTP(w, r2)
		}
		if s.Invalidate != nil && receive {
			// the push (if the hook accepted it) has landed: HEAD may have moved
			s.Invalidate(eng)
		}
	})
}

// isPush reports whether r is part of a push (receive-pack).
func isPush(r *http.Request) bool {
	return strings.HasSuffix(r.URL.Path, "/git-receive-pack") ||
		(strings.HasSuffix(r.URL.Path, "/info/refs") && r.URL.Query().Get("service") == "git-receive-pack")
}

func (s *Server) inherit() []string {
	env := []string{"PATH", "HOME", "TMPDIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy"}
	return append(env, s.InheritEnv...)
}
