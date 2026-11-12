# M30 — git pre-commit hook

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Read `2026-11-11-yars-roadmap-to-v1.md` first. Steps use checkbox (`- [ ]`) syntax.

**Goal:** in a pentester's clone, every commit sends the findings being committed to the YARS server, which checks them with the same rules the Check button runs (regex, built-in, script and AI), and the hook prints what the server found. It never stops a commit.

**Architecture:** the rules run on the server, never in the clone, so the result is the server's own and the clone needs no rules, no scripts and no AI key. The server gains one endpoint next to the git endpoint, `POST /git/e/<id>/lint`, behind the same login as `git push` (password or git token). `yars lint --staged` in the clone reads each staged `finding.md` from git's index, posts it, and prints the answer. It finds the server from the clone's `origin` URL and gets the login from git's own credential helper, so there is nothing new to configure. `yars hook install` writes the `pre-commit` hook that calls it.

**Spec:** `docs/open-decisions-2026-11-07.md` "Anything else" (a pre-commit hook that runs the check and marks issues), R8 (the hook only warns), Q5 (the user expects rules, AI included, to have run by commit time), and the user's answer of 2026-11-11: "it should just ask the server and run the commands as they are on the server".

**Branch:** `pr/24-precommit-hook` from `pr/14-hygiene-ci`.

## Review focus

1. The hook must check what is being committed (the index), not the work tree (task 2 `TestLintStagedReadsIndexNotWorktree`).
2. A server that is down, slow or refuses the login must never block or hang a commit: the hook says so and exits 0 within its time limit (task 2 `TestLintStagedServerDown`, `TestLintStagedTimesOut`).
3. The endpoint must not let someone outside an engagement's team run rules against it or learn that it exists (task 1 `TestLintEndpointTeamOnly`).
4. Posted text is checked, never stored: no commit, no check run, no chat thread (task 1 `TestLintEndpointStoresNothing`).
5. A hook the user wrote must not be overwritten (task 3 `TestHookInstallKeepsForeignHook`).

---

### Task 1: the server's lint endpoint

**Files:** modify `internal/gitserve/gitserve.go` (`Server`, `Handler`), `internal/gitserve/gitserve_test.go`, `cmd/yars/main.go` or `cmd/yars/serve.go` (`cmdServe` sets the new field), `internal/store/checks.go` or `checks_open.go` (new method)

**Interfaces produced:**

```go
package store
// LintContent checks raw (a finding.md as it would be committed to engagement
// engID) with every rule, as a check run does, and returns the violations
// that are not dismissed on that finding. Nothing is stored.
func (s *Store) LintContent(ctx context.Context, engID string, raw []byte) ([]rules.Violation, error)

package gitserve
// Server gains:
	// Lint, when set, answers POST /git/e/<id>/lint.
	Lint func(ctx context.Context, eng string, raw []byte) ([]rules.Violation, error)
// LintMaxBody caps a posted finding.
const LintMaxBody = 1 << 20
```

Rules:
1. `LintContent`: `finding.Parse(raw)`; a parse error is `ErrInvalidValue` with the parser's message. The engagement must exist. It runs `s.Linter.Lint(ctx, f, rules.All)` (no linter: no violations), then drops the violations dismissed for that finding id (`s.undismissed`). It writes nothing.
2. Route: in `Handler`, after the login, the team check (`CanSee`) and the token's engagement check, and before `git http-backend`: a `POST` whose path is exactly `/git/e/<id>/lint` is answered by the server itself. Any other method on that path is 405.
3. Request: the body is the raw `finding.md`, at most `LintMaxBody` (larger: 413). Response `200`, `Content-Type: application/json`: `{"violations":[{"rule":"…","level":"error|warning","message":"…","target":"…","quote":"…"}]}` (an empty list when clean). A file that does not parse: `422` with `{"error":"<message>"}`. No `Lint` func: `404`.
4. A read-only git token may lint (it reads only). The write deadline is lifted for this route as for the other git routes (it already is: `/git/` is wrapped in `longLived`), since AI rules can take up to the engine's 90 s budget.
5. `cmdServe` sets `gs.Lint = st.LintContent`.

- [x] **Step 1: write the failing tests.**
  - `TestLintContent` (`store`, with the rule file the check tests use): a finding whose title ends with a dot returns the `title-no-trailing-dot` violation; a clean one returns none; an unparseable one is `ErrInvalidValue`.
  - `TestLintContentHonoursDismissals`: after `DismissWhy` on that violation for `F-001`, posting the same content with id `F-001` returns none.
  - `TestLintEndpointReturnsViolations` (`gitserve`): `POST /git/e/acme/lint` with Basic auth returns 200 and the JSON list.
  - `TestLintEndpointNeedsLogin`: without credentials, 401 with `WWW-Authenticate`.
  - `TestLintEndpointTeamOnly`: a user who is not on the team gets 403, the same answer a clone gets.
  - `TestLintEndpointStoresNothing`: after the call the engagement repo's HEAD, the number of check runs and the number of chat messages are unchanged.
  - `TestLintEndpointUnparseable`: 422 with the message; `TestLintEndpointTooLarge`: 413; `TestLintEndpointGetIs405`.
  - `TestLintEndpointRestrictedToken`: a git token limited to another engagement gets 403; a read-only token for this one gets 200.
- [x] **Step 2:** run `go test ./internal/store ./internal/gitserve -run Lint`. Expected: FAIL.
- [x] **Step 3:** implement.
- [x] **Step 4:** run `go test ./internal/store ./internal/gitserve ./cmd/yars`. Expected: PASS.
- [x] **Step 5:** commit: `feat(git): the server checks a posted finding with every rule`.

### Task 2: `yars lint --staged`

**Files:** create `cmd/yars/lintstaged.go`, `cmd/yars/lintstaged_test.go`; modify `cmd/yars/main.go` (`cmdLint`: the new flags)

**Interfaces produced:**

```go
// lintStaged sends the findings staged in the engagement clone at dir to its
// server and prints what the server found. It returns the number of errors
// and warnings; err is set only for a problem with the clone itself.
func lintStaged(ctx context.Context, dir string, out io.Writer) (errs, warns int, err error)
// lintURL turns an origin URL (http[s]://host[:port]/git/e/<id>[.git]) into
// its lint endpoint; ok is false for any other URL.
func lintURL(origin string) (url string, ok bool)
// gitCredential asks git's credential helper for the login of url.
func gitCredential(dir, url string) (user, pass string, err error)
// lintTimeout bounds the whole hook run.
var lintTimeout = 120 * time.Second
```

Rules:
1. New flags of `yars lint`: `--staged` (check the staged findings of the clone in the current folder, or in `--data`) and `--warn-only` (always exit 0).
2. Staged files: `git diff --cached --name-only --diff-filter=ACM -z`, kept when they match `findings/<dir>/finding.md`; each is read with `git show :<path>`. None staged: print nothing, return.
3. The origin is `git config --get remote.origin.url`. When `lintURL` does not recognise it (a main clone, a file path, another host layout): print `yars: this clone's origin is not a YARS engagement (/git/e/<id>); nothing checked` and return.
4. The login comes from `git credential fill` (stdin: `url=<origin>` and a blank line; run with `GIT_TERMINAL_PROMPT=0` so it never asks). No stored login: print `yars: no saved login for <host>; run git fetch once, then commit again` and return. A URL that already carries `user:pass@` uses that.
5. Each finding is one `POST` to the lint URL with Basic auth and the raw file as the body. The whole run shares one context with `lintTimeout`.
6. Output, per violation, in `cmdLint`'s existing format: `<path> <level> <rule>: <message> ("<quote>") [<target>]`. A 422 prints `<path> error parse: <message>` and counts as one error.
7. A failure to reach the server, a timeout, or a 401/403/5xx prints one line and stops: `yars: could not ask <host>: <reason>; nothing checked`. It counts no errors.
8. The last line, when anything was checked: `yars: <E> errors, <W> warnings in <F> findings`, plus ` (commit not blocked)` with `--warn-only`.
9. Exit code: 1 when there are errors and `--warn-only` is not set; otherwise 0.

- [x] **Step 1: write the failing tests.** The server is an `httptest.Server` with a handler that records requests and answers a programmed body; the clone is a temp git repository with `remote.origin.url` set to `<server URL with user:pass@>/git/e/acme`.
  - `TestLintURL`: `http://h:8080/git/e/acme` and `https://h/git/e/acme.git` map to `…/git/e/acme/lint`; `http://h/git/yars` and `/tmp/x` are not ok.
  - `TestLintStagedReadsIndexNotWorktree`: stage a finding, change it in the work tree without staging: the posted body equals the staged content.
  - `TestLintStagedOnlyStagedFindings`: a second, unstaged finding is not posted; a staged file that is not a `finding.md` is not posted.
  - `TestLintStagedPrintsViolations`: the server answers one error and one warning: both lines are printed, then `yars: 1 errors, 1 warnings in 1 findings`; the exit code is 1, and 0 with `--warn-only` (with `(commit not blocked)`).
  - `TestLintStagedSendsBasicAuth`: the request's Basic auth is the login from the URL.
  - `TestLintStagedServerDown`: the server is closed: one `could not ask` line, exit code 0 even without `--warn-only`.
  - `TestLintStagedTimesOut`: the handler sleeps; with `lintTimeout = 200ms` the command returns in under 2 s with the `could not ask` line.
  - `TestLintStagedRefusedLogin`: a 401 answer prints `could not ask` with `login refused`.
  - `TestLintStagedNotAnEngagementClone`: origin `http://h/git/yars` prints the "not a YARS engagement" line and posts nothing.
  - `TestLintStagedUnparseable`: a 422 answer prints a `parse` line.
- [x] **Step 2:** run `go test ./cmd/yars -run "LintStaged|LintURL"`. Expected: FAIL.
- [x] **Step 3:** implement.
- [x] **Step 4:** run `go test ./cmd/yars`. Expected: PASS.
- [x] **Step 5:** commit: `feat(cli): yars lint --staged asks the server to check what is being committed`.

### Task 3: `yars hook install`

**Files:** modify `cmd/yars/main.go` (`main`: `case "hook"` sends `pre-receive` to `cmdHook` and `install` to the new function; `usage`), create `cmd/yars/hookinstall.go`, `cmd/yars/hookinstall_test.go`

**Interfaces produced:**

```go
// cmdHookInstall writes the pre-commit hook into every engagement
// repository of the clone at --data (default: the current folder).
func cmdHookInstall(args []string, out io.Writer) error
// hookMarker is the line that tells our hook from someone else's.
const hookMarker = "# installed by yars hook install"
```

Rules:
1. The clone is a main clone (it has `.yars/config.yaml`): the targets are every `engagements/<id>` that is a git repository. Or it is an engagement clone (it has `engagement.yaml`): the target is itself. Neither: `"<dir> is not a YARS clone"`.
2. The hook path of a target is the output of `git -C <target> rev-parse --git-path hooks/pre-commit` (a submodule's hooks live under the main clone's `.git/modules`), made absolute against the target.
3. The hook's content, with `<bin>` the absolute path of the running binary (`os.Executable`), quoted with `shellQuote`:

```sh
#!/bin/sh
# installed by yars hook install
test -x <bin> || exit 0
exec <bin> lint --staged --warn-only
```

4. An existing hook that contains `hookMarker` is replaced. One that does not is left alone and reported: `<path>: a pre-commit hook exists already; add this line to it: <bin> lint --staged --warn-only`.
5. Output: one line per target, `installed <engagement id>` or the line above; then `<N> installed`.

- [x] **Step 1: write the failing tests.**
  - `TestHookInstallWritesEveryEngagement`: a main clone with two engagement repositories: both get an executable hook holding `hookMarker` and `lint --staged --warn-only`.
  - `TestHookInstallSubmodulePath`: for a real `git clone --recurse-submodules` of a data folder (built as `cmd/yars/push_test.go` does), the hook lands where `git rev-parse --git-path hooks/pre-commit` points.
  - `TestHookInstallKeepsForeignHook`: a hand-written hook is unchanged and the output names the line to add.
  - `TestHookInstallReplacesOwnHook`: installing twice leaves one hook with the current binary path.
  - `TestHookNeverBlocksCommit`: end to end against a real server (as `push_test.go` starts one), with a rule that the finding breaks: `git commit` exits 0 and its stderr has the rule id and `commit not blocked`.
  - `TestHookCommitWorksWithServerDown`: the same clone after the server stopped: `git commit` exits 0 with the `could not ask` line.
  - `TestHookInstallNotAClone`.
- [x] **Step 2–4:** fail, implement, pass.
- [x] **Step 5:** commit: `feat(cli): yars hook install`.

### Task 4: documents

**Files:** modify `docs/git.md`, `README.md`

- [x] **Step 1:** `docs/git.md`, new section "Check before you commit": run `yars hook install` once per clone and again after cloning a new engagement; each commit then sends the staged findings to the server, which runs the same rules as the Check button, AI rules included, and can take as long as they do; nothing is stored on the server; it uses the login git already saved for the clone; it never blocks a commit; the push is checked again by the server.
- [x] **Step 2:** README: one line under Quick start pointing to that section.
- [x] **Step 3:** run `go test ./internal/web -run Docs` (the docs pages are rendered from these files). Commit: `docs(git): check before you commit`. Push the branch and open PR #24 (title `Pre-commit hook: the server checks staged findings`).
