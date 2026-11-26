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
- `/setup` asks for a setup code. `yars serve` logs the code at each start while there is no account. `yars useradd --admin` needs no code.
- Settings › Tokens › New token asks for your password. `yars token add` does not.
- Only a finding's author or a director sends it to a destination. The export page ticks the findings you may send. Downloads and the preview stay open to the team.

### Fixed

- The cache of rendered Markdown is limited in bytes; a text over 64 KiB is not cached.
