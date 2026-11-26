# Changelog

What changed for people who run or use YARS. Newest first.

## Unreleased

### Added

- Settings › About shows the version, the license and a link to the source.
- The licence texts of the vendored fonts and htmx ship with the binary; `NOTICE` lists all third-party work.
- `SECURITY.md`, `CONTRIBUTING.md` and issue templates.
- `log.level` (`debug`, `info`, `warn`, `error`) and `log.format` (`text`, `json`) in `.yars/config.yaml`, and `yars serve --log-level`, set what the service log holds and how it is written ([docs/config.md](docs/config.md)). Both keys are read at the start.
- The service log has one line for each request to the website, the git endpoint and MCP: an ID, the method, the route, the status, the time taken, the account, the token's ID, the engagement and the finding. A request over 2 s is a warning. Static files are logged at `debug`. A handler's panic is one line with the whole stack trace in `stack`.
- The service log holds IDs and usernames, never text: an attribute named like a password, a token's value, a key, a cookie, a title, a reason or other text is dropped, and an error's text loses a finding's folder name (its ID stays), an attachment's name, and the login and query of an address. The error of a failed git command leaves out the commit message.
- Every response carries its request's ID as `X-Request-ID`. An internal error shows it on the page and in the toast (`Request 4f2a9c1b`), and the error's log line has the same ID.
- The background work writes a line when it ends, with the time taken and the outcome: a check run, an AI call, an export, a webhook delivery, a mail, a push (accepted or refused), a backup download, a restore upload and the daily prune. A webhook delivery that is tried again, a failed AI call, a mail that is not sent and a wait of over 5 seconds for a repository's lock are warnings. The start line names the version, the schema, the workflow, the address and whether AI, SMTP and pandoc are on.
- An AI call the provider refused is one `warn` line, `ai call failed`, with `status` and `host`. The line `ai: the provider refused a call` is gone.
- A webhook delivery that got no HTTP answer says why in `err`, in one fixed word (`no answer`, `redirect refused`, `secret`, `address`, `removed`, `disabled`, `database`). A delivery dropped because its webhook was turned off is an `info` line, `webhook delivery dropped`.
- `yars status --data <dir>` prints what the running server does now: the checks running and queued, the waiting webhook deliveries, the open event streams, the repository locks and the last 200 warnings and errors. It reads the server over a socket in the data folder (`.yars/status.sock`), needs no password, and runs as the service account. A second `yars serve` on the same data folder leaves the first one's socket alone: it writes one `warn` line and runs without `yars status`.
- Admin › System has two new panels. Current state shows the same as `yars status`. Log shows the last 200 warnings and errors of the service log; they are kept in memory and lost at a restart.
- Admin › System › Log has the switch Debug level for 15 minutes: it sets the service log to `debug` without a restart and turns itself off. Each change is in Admin › Activity.
- `docs/deploy.md` has a Logs section: the journalctl commands, the levels, the fields, what a line never holds, the request ID, and a fail2ban example for the failed-login lines in their new form.

### Changed

- The Go module is `github.com/abno525/yars`: `go install github.com/abno525/yars/cmd/yars@latest` builds the binary.
- The binary embeds the six developer pages only.
- `docs/deploy.md`: a `0700` data folder, systemd hardening, backup pruning, the minimum git version, uninstalling.
- `docs/rules.md` covers every kind of rule, its limits and its failures.
- `docs/known-limits.md` lists today's limits by subject.
- The team of an archived engagement cannot change. Reopen the engagement first.
- Only an admin sets where a service destination publishes (project, issue type, space, parent page).
- Only a director pushes `README.md` to the main repository, as `.gitignore`.
- The pre-commit check (`yars lint --staged`) with a Git token runs script and AI rules only when the token has the Run checks action. Other tokens get the pattern and built-in rules.
- `yars seed` gives its accounts a random password and prints it. Without the size flags it makes 2 engagements of 20 findings with 50 messages (before: 50 of 300, with 10,000).
- `/setup` asks for a setup code. `yars serve` logs the code at each start while there is no account. `yars useradd --admin` needs no code.
- Settings › Tokens › New token asks for your password. `yars token add` does not.
- `ai.api_key_env` and `smtp.password_env` in `.yars/config.yaml` must name a variable that starts with `YARS_`. A file that names another one is refused on save and on push, and `yars serve` does not start with it. Rename the variable in the service's environment, set the new name in `.yars/config.yaml` in the data folder and commit it there ([docs/config.md](docs/config.md)).
- The clone and MCP addresses on the pages come from `base_url`. Without it they use the request's host, and `https` only when the server runs with `--https` or a certificate: the `X-Forwarded-Proto` header is no longer read. A server behind a TLS proxy that runs without `--https` and without `base_url` now shows `http` addresses: set `base_url`. `yars serve` logs at the start when `base_url` is not set.
- A login ends 30 days after it was made at the latest, however much it is used: sessions older than that end at the upgrade. The session cookie lives as long as its session (before: always 14 days, whatever Admin › System › Retention said). Sessions set to 0 days there means the default 14; such sessions are now deleted when they end.
- Only a finding's author or a director sends it to a destination. The export page ticks the findings you may send. Downloads and the preview stay open to the team.
- YARS writes the data folder for the service account alone: folders `0700`, files `0600`, scripts `0700`, and git runs with a umask of `077`. A restore writes these modes too. An existing data folder is not changed: `chmod -R go= <data folder>` closes it.
- The umask of `077` is that of rule scripts, script destinations and pandoc too: a file such a script makes, also outside the data folder, is `0600`. A script whose files another account reads sets its own umask (`umask 022`).
- Standard workflow: an error on your own finding is dismissed, and restored, by another reviewer or a director, whatever your role. Warnings and the simple workflow are unchanged. Dismissals made before stay.
- `yars useradd` and `yars passwd` on a terminal ask for the password twice and do not show it. A password piped to them is a temporary one: the next login asks for a new one, and until then the account's git logins and tokens are refused.
- `yars token add` makes a token that expires after 90 days (before: never). `--days N` or `--expires YYYY-MM-DD` sets another end, `--expires never` or `--days 0` none. A past date is refused. The printed line names the expiry.
- The service log of `yars serve` has a new form: every line is `time=… level=… msg=… key=value …` on stderr (before: free text). A filter on the old text must change. A failed login is now `msg="login failed" user=… remote=…` (git: `msg="git login failed"`), a lockout `msg="login locked"`, the setup code `setup_code=…`. What `git http-backend` and the web server itself report are lines of the same form.
- `yars export`, `yars lint` and `yars mcp` write a finding or an engagement they skip to stderr in the same form.
- `yars export` writes its file `0600` and does not replace a file that is there. `--force` replaces it. A device or a pipe named by `--out` (`/dev/stdout` into a pipe, a FIFO) is written into as before.

### Fixed

- The cache of rendered Markdown is limited in bytes; a text over 64 KiB is not cached.
- The editor's preview takes only a finding's folder name in its address.
- Files waiting for download after a send are limited to 256 MiB per user, dropped after 10 minutes by a timer, and served only under the engagement they were made in.
- A reason (Return, Withdraw, Revert, dismissing a check) has at most 4,000 characters, on the finding page and over MCP as in the bulk bar.
- An approval and a sign-off are bound to the full SHA-256 of the finding's file (before: its first 64 bits), and so are the version a Sign off, Approve or Complete button names and the check run they wait for. Approvals, sign-offs and check runs from before the upgrade keep counting. A finding page left open across the upgrade must be loaded again before Sign off or Approve. Over MCP, `read_finding`'s `hash` is the full digest.
- The service log has a line for each failed password login (website and git), with the name and the address, and one for a lockout. A failed AI call logs its status and the provider's host only, no longer the start of the provider's answer.
- A restore takes no git hook from the ZIP and writes each repository's git config again with its basic settings only. A ZIP whose `.git` is a file or holds no `HEAD`, or that holds a git folder (`HEAD`, `objects`, `refs`) outside `.git`, is refused.
- A send to Confluence or Jira and a webhook delivery follow no redirect to another host, another port or from `https` to `http`: the key, the signature and the text go to the configured address only. Such a redirect fails the send with `redirect to <host> refused`.
- Admin › Rules › Test bench runs with a POST: a link cannot start scripts or AI calls. A long Run on engagement is no longer cut off after 60 seconds.
- Over MCP a failure of the server itself answers `server_error` with the message `internal error`, and `read_finding` gives that as an action's reason. The error's own words (a path, a database statement) go to the service log only. A finding file that does not parse still says why.
- The browser keeps no page snapshots (htmx's history cache is off; Back to such a page loads it again). A draft kept after an expired session is stored under its account's name, so another account on the same browser is not offered it, and Log out removes the account's drafts. A draft is kept 14 days: an older one, of any account, is removed when a page loads. Drafts kept by an earlier version are removed.
- Dismissing a check result and restoring it are in the audit log: who, the finding, the rule, its level and place, and the reason. A dismissal without a reason is refused by the server itself, not only by the page.
- Fix with AI sends the section between the same delimiters as an AI check, so text in a finding cannot pass as the rule.
- A new account cannot take a username that differs from another only in the case of its ASCII letters (`Alice` beside `alice`). Accounts that already do keep working; `yars serve` logs them at start. The database schema is 25.
- Live updates of an open page end within 25 seconds of a logout, a disabled account or leaving the team. One account holds at most 20 live streams.
- A merge into a complete or reported finding keeps its approval also when the source brings a new asset (before: the finding fell back to verification). The `finding.updated` webhook of a metadata edit names the reviewers.
- The Merge page has the panel Not moved: the source's details rows and CVSS, which the target does not take.
- A push of a finding or a template with text between the front matter and the first `## ` heading is refused: no page shows such text and no export carries it. A file that already has it still takes other edits.
- A push of a finding or a template whose front matter the website cannot edit is refused: the whole of it between `{ }`, an indented top-level key, a value continued at the first column ([docs/git.md](docs/git.md)). Before, every later edit of its title, severity, CVSS, details or assets failed, and it stopped a rename in Admin › Structure. A file the server already holds in such a form is not changed: it still stops the rename until it is rewritten.
- Saving the reviewers of a finding from a page opened before someone else changed them is refused (`the reviewers changed since you opened the page; choose again`): the reviewer added meanwhile, and their sign-off, stay. Assign all adds to the list as it is. Over MCP, `read_finding` gives `field_bases.reviewers`, and `set_field reviewers` with it as `base` answers `conflict` when the list changed.
- Each start of `yars serve` removes the files in the engagements' `findings/` folders that no commit holds, and logs the engagement and a count (`warn`). A stop between a file's write and its commit left a new finding's folder or a new attachment that every page read as real. Nothing is removed while another `yars serve` answers on the data folder, nor in the main repository. A file an operator put into a `findings/` folder by hand, without a commit, is removed too.
- An engagement repository a stop left without its first commit no longer stops the start.
- A service account whose git config sets `init.defaultRefFormat=reftable` works: YARS makes its repositories with refs as files, and reads the commit of a repository that is reftable already by asking git.
- Admin › Structure renames a name in findings, templates and report text only when its own row was retyped. Removing one name and adding another in the same save is a removal and an addition (before: read as a rename, which rewrote every finding): a removed name that is still used is refused.
