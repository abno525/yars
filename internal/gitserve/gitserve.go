// Package gitserve exposes the data repos over git smart HTTP (git
// http-backend) behind YARS accounts, and installs the pre-receive hook that
// enforces the push rules: the main repo at /git/yars (settings plus every
// engagement as a submodule) and each engagement's own repo at /git/e/<id>.
package gitserve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/abno525/yars/internal/auth"
	"github.com/abno525/yars/internal/config"
	"github.com/abno525/yars/internal/db"
	"github.com/abno525/yars/internal/gitrepo"
	"github.com/abno525/yars/internal/policy"
	"github.com/abno525/yars/internal/rules"
	"github.com/abno525/yars/internal/store"
)

// RepoName is the fixed name in the clone URL: http(s)://host/git/yars.
const RepoName = "yars"

// DefaultMaxBody is the largest chunked request body (a push) accepted.
const DefaultMaxBody = 2 << 30

// LintMaxBody caps a posted finding (POST /git/e/<id>/lint).
const LintMaxBody = 1 << 20

// lintReadTimeout bounds reading a posted finding: /git/ has no read
// deadline (pushes take long), but a finding is at most LintMaxBody.
var lintReadTimeout = 60 * time.Second

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
	// MaxBody caps a request body sent without a length (chunked), which
	// is spooled to a temporary file; 0 = DefaultMaxBody.
	MaxBody int64
	// Lint, when set, answers POST /git/e/<id>/lint: it checks a posted
	// finding.md with every rule and stores no commit and no check run
	// (yars lint --staged).
	Lint func(ctx context.Context, eng string, raw []byte) ([]rules.Violation, error)

	mu      sync.Mutex
	cache   map[string]cached
	flights map[string]*flight // credential checks running, keyed as cache
	ready   map[string]string  // repos already configured for pushes: the hook each got ("" = none)

	setupMu     sync.Mutex       // one repository setup at a time (git's config lock)
	beforeSetup func(dir string) // tests: called as a repository's setup starts
}

// ensureSetup sets r up for pushes unless it is already: the first requests
// to a new engagement repository wait for one setup instead of racing.
func (s *Server) ensureSetup(r *gitrepo.Repo) error {
	isReady := func() bool {
		s.mu.Lock()
		hook, ok := s.ready[r.Dir]
		s.mu.Unlock()
		if !ok {
			return false
		}
		// a folder replaced while the server ran has lost its hook
		_, err := os.Stat(hook)
		return hook == "" || err == nil
	}
	if isReady() {
		return nil
	}
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if isReady() { // set up while this one waited
		return nil
	}
	return s.setupRepo(r)
}

type cached struct {
	user config.User
	exp  time.Time
}

// flight is one credential check in progress; done closes when u and err
// are set.
type flight struct {
	done chan struct{}
	u    config.User
	err  error
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
	if s.beforeSetup != nil {
		s.beforeSetup(r.Dir)
	}
	gd, err := r.GitDir()
	if err != nil {
		return err
	}
	hooks := filepath.Join(gd, "hooks")
	hook := ""
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
		hook = filepath.Join(hooks, "pre-receive")
		if err := os.MkdirAll(hooks, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(hook, []byte("#!/bin/sh\nexec "+cmd+"\n"), 0o755); err != nil {
			return err
		}
	}
	s.mu.Lock()
	if s.ready == nil {
		s.ready = map[string]string{}
	}
	s.ready[r.Dir] = hook
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
func (s *Server) check(user, pw string) (config.User, error) {
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
			return cur, nil
		}
		s.mu.Lock()
		delete(s.cache, key)
		s.mu.Unlock()
	}
	// a miss: expired logins leave the cache
	now := time.Now()
	s.mu.Lock()
	for k, c := range s.cache {
		if !now.Before(c.exp) {
			delete(s.cache, k)
		}
	}
	s.mu.Unlock()
	return s.checkOnce(key, user, pw)
}

// checkOnce checks credentials once for all the requests that bring the
// same ones (key) while the check runs, and caches a success: git's first
// requests of a clone come at once, and as many login attempts in flight
// would pass the lockout's limit (D27) and be refused. Only a pass is
// shared: a refused request checks again on its own, so wrong passwords
// count as before.
func (s *Server) checkOnce(key, user, pw string) (config.User, error) {
	s.mu.Lock()
	if f, ok := s.flights[key]; ok {
		s.mu.Unlock()
		<-f.done
		if f.err != auth.ErrRefused {
			return f.u, f.err
		}
		u, err := s.Auth.CheckErr(user, pw)
		if err == nil {
			s.mu.Lock()
			s.cache[key] = cached{u, time.Now().Add(10 * time.Minute)}
			s.mu.Unlock()
		}
		return u, err
	}
	if s.flights == nil {
		s.flights = map[string]*flight{}
	}
	// refused until the check says otherwise (a panic in it too)
	f := &flight{done: make(chan struct{}), err: auth.ErrRefused}
	s.flights[key] = f
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if f.err == nil {
			s.cache[key] = cached{f.u, time.Now().Add(10 * time.Minute)}
		}
		delete(s.flights, key)
		s.mu.Unlock()
		close(f.done)
	}()
	f.u, f.err = s.Auth.CheckErr(user, pw)
	return f.u, f.err
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
		err := auth.ErrRefused
		switch {
		case !ok: // no bcrypt for requests without credentials
		case s.Tokens != nil && strings.HasPrefix(pw, "yars_"):
			var info db.TokenInfo
			var owner config.User
			owner, info, err = s.Tokens.Lookup(pw, db.TokenGit)
			if err != auth.ErrRefused && info.User != name {
				err = auth.ErrRefused // the token's own account only
			}
			u, tok = owner, &info
		default:
			u, err = s.check(name, pw)
		}
		if err == auth.ErrMustChange {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if err != nil {
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
		if eng != "" && r.URL.Path == root+"/lint" {
			// answered here, after the login, the team and the token's
			// engagements: a read-only token may lint (it only reads)
			s.lint(w, r, u, eng)
			return
		}
		if gitErr != nil {
			http.Error(w, "git not available", http.StatusInternalServerError)
			return
		}
		if err := s.ensureSetup(repo); err != nil {
			http.Error(w, "repository setup failed", http.StatusInternalServerError)
			return
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
		if r2.Method == http.MethodPost && r2.ContentLength < 0 {
			// git sends a pack bigger than its http.postBuffer chunked, and
			// net/http/cgi refuses chunked bodies: spool it so it has a length
			limit := s.MaxBody
			if limit <= 0 {
				limit = DefaultMaxBody
			}
			f, err := spool(http.MaxBytesReader(w, r2.Body, limit))
			if err != nil {
				var tooBig *http.MaxBytesError
				if errors.As(err, &tooBig) {
					http.Error(w, fmt.Sprintf("request body over %d MiB", limit>>20), http.StatusRequestEntityTooLarge)
					return
				}
				http.Error(w, "could not read the request body", http.StatusBadRequest)
				return
			}
			defer func() { f.Close(); os.Remove(f.Name()) }()
			st, err := f.Stat()
			if err != nil {
				http.Error(w, "could not read the request body", http.StatusInternalServerError)
				return
			}
			r2.Body, r2.ContentLength, r2.TransferEncoding = f, st.Size(), nil
		}
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

// spool copies a request body of unknown length to a temporary file and
// returns it rewound.
func spool(body io.Reader) (*os.File, error) {
	f, err := os.CreateTemp("", "yars-git-body-*")
	if err != nil {
		return nil, err
	}
	if _, err = io.Copy(f, body); err == nil {
		_, err = f.Seek(0, io.SeekStart)
	}
	if err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return f, nil
}

// lintViolation is one violation in the lint answer.
type lintViolation struct {
	Rule    string `json:"rule"`
	Level   string `json:"level"`
	Message string `json:"message"`
	Target  string `json:"target"`
	Quote   string `json:"quote"`
}

// lint answers POST /git/e/<eng>/lint: the body is a finding.md as it would
// be committed; the answer is {"violations":[…]} (an empty list when clean),
// 422 {"error":…} for a file that does not parse. Nothing is stored. The
// rules' AI calls are recorded under u (D24).
func (s *Server) lint(w http.ResponseWriter, r *http.Request, u config.User, eng string) {
	if s.Lint == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tooBigMsg := fmt.Sprintf("a finding over %d KiB", LintMaxBody>>10)
	if r.ContentLength > LintMaxBody {
		http.Error(w, tooBigMsg, http.StatusRequestEntityTooLarge)
		return
	}
	// a client that stalls part way does not hold the handler. After a
	// whole body the deadline is lifted before the rules run (an expired
	// one would cancel the request's context, the AI rules); after a failed
	// read it stays, and the body is closed, so net/http answers and drops
	// the connection instead of waiting for the rest
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Now().Add(lintReadTimeout))
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, LintMaxBody))
	if err == nil {
		rc.SetReadDeadline(time.Time{})
	} else {
		r.Body.Close()
	}
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, tooBigMsg, http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "could not read the request body", http.StatusBadRequest)
		return
	}
	ctx := rules.WithCaller(r.Context(), rules.Caller{User: u.Username, Eng: eng})
	vs, err := s.Lint(ctx, eng, raw)
	answer := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	switch {
	case errors.Is(err, store.ErrInvalidValue):
		answer(http.StatusUnprocessableEntity, map[string]string{"error": strings.TrimPrefix(err.Error(), store.ErrInvalidValue.Error()+": ")})
		return
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
		return
	case err != nil:
		http.Error(w, "could not check the finding", http.StatusInternalServerError)
		return
	}
	out := make([]lintViolation, 0, len(vs))
	for _, v := range vs {
		out = append(out, lintViolation{Rule: v.Rule, Level: v.Level, Message: v.Message, Target: v.Target, Quote: v.Quote})
	}
	answer(http.StatusOK, map[string][]lintViolation{"violations": out})
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
