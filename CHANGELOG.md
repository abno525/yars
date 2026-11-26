# Changelog

What changed for people who run or use YARS. Newest first.

## Unreleased

### Added

- Settings › About shows the version, the license and a link to the source.
- The licence texts of the vendored fonts and htmx ship with the binary; `NOTICE` lists all third-party work.
- `SECURITY.md`, `CONTRIBUTING.md` and issue templates.

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
- `yars useradd` and `yars passwd` on a terminal ask for the password twice and do not show it. A password piped to them is a temporary one: the next login asks for a new one, and until then the account's git logins and tokens are refused.
- `yars export` writes its file `0600` and does not replace a file that is there. `--force` replaces it.

### Fixed

- The cache of rendered Markdown is limited in bytes; a text over 64 KiB is not cached.
- The editor's preview takes only a finding's folder name in its address.
- Files waiting for download after a send are limited to 256 MiB per user, dropped after 10 minutes by a timer, and served only under the engagement they were made in.
- A reason (Return, Withdraw, Revert, dismissing a check) has at most 4,000 characters, on the finding page and over MCP as in the bulk bar.
- An approval and a sign-off are bound to the full SHA-256 of the finding's file (before: its first 64 bits), and so are the version a Sign off, Approve or Complete button names and the check run they wait for. Approvals, sign-offs and check runs from before the upgrade keep counting. A finding page left open across the upgrade must be loaded again before Sign off or Approve. Over MCP, `read_finding`'s `hash` is the full digest.
- The service log has a line for each failed password login (website and git), with the name and the address, and one for a lockout. A failed AI call logs its status and the provider's host only, no longer the start of the provider's answer.
- A restore takes no git hook from the ZIP and writes each repository's git config again with its basic settings only. A ZIP whose `.git` is a file or holds no `HEAD`, or that holds a git folder (`HEAD`, `objects`, `refs`) outside `.git`, is refused.
- Fix with AI sends the section between the same delimiters as an AI check, so text in a finding cannot pass as the rule.
- A new account cannot take a username that differs from another only in the case of its ASCII letters (`Alice` beside `alice`). Accounts that already do keep working; `yars serve` logs them at start. The database schema is 25.
- Live updates of an open page end within 25 seconds of a logout, a disabled account or leaving the team. One account holds at most 20 live streams.
