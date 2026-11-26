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
- Only an admin sets where a service destination publishes (project, issue type, space, parent page), a script destination's script and a pandoc template. Only an admin pushes scripts and templates to `.yars/exporters`.
- Only a director pushes `README.md` to the main repository, as `.gitignore`.
- The pre-commit check (`yars lint --staged`) with a Git token runs script and AI rules only when the token has the Run checks action. Other tokens get the pattern and built-in rules.
- `yars seed` gives its accounts a random password and prints it. Without the size flags it makes 2 engagements of 20 findings with 50 messages (before: 50 of 300, with 10,000).
- `/setup` asks for a setup code. `yars serve` logs the code at each start while there is no account. `yars useradd --admin` needs no code.
- Settings › Tokens › New token asks for your password. `yars token add` does not.
- Only a finding's author or a director sends it to a destination. The export page ticks the findings you may send. Downloads and the preview stay open to the team.

### Fixed

- The cache of rendered Markdown is limited in bytes; a text over 64 KiB is not cached.
- The editor's preview takes only a finding's folder name in its address.
- Files waiting for download after a send are limited to 256 MiB per user, dropped after 10 minutes by a timer, and served only under the engagement they were made in.
